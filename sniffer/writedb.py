#! /usr/bin/env python
"""

python writedb.py sessions.db platform *.pkt

Write all requests to the db

"""

import sys
import sqlite3

def extract_url(req):
    lines = req.split('\n')
    header = lines[0]
    x = header.split(' ')
    path = ' '.join(x[1:len(x)-1]).strip()
    headers = {}
    for hdr in lines[1:]:
        if len(hdr.strip()) > 0:
            headers[hdr.split(': ')[0]] = hdr.split(': ')[1].strip()
    return 'http://' + headers['Host'] + path


if __name__ == '__main__':
    dbname = sys.argv[1]
    platform = sys.argv[2]
    packets = sys.argv[3:]

    conn = sqlite3.connect(dbname)
    c = conn.cursor()
    c.execute('INSERT INTO sessions (platform, vid, pid, bcid, hasAd, time) VALUES (?, ?, ?, ?, ?, ?)', (platform, '', '', '', 0, 0))
    id = c.lastrowid

    for pkt in packets:
        time = pkt.split('.')[0]
        f = open(pkt, 'r')
        content = f.read()
        f.close()
        c.execute('INSERT INTO requests (sessionId, time, url, content) VALUES (?, ?, ?, ?)', (id, time, extract_url(content), content))

    conn.commit()
    conn.close()

