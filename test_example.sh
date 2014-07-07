#!/bin/sh

curl -v -d d=1 http://ip.ptsang.net/  # Non-GET 
curl -v http://ip.ptsang.net/         # Index
curl -v http://ip.ptsang.net/123456789/123456789/123456789/123456789/123456789/123456789/123456789/123456789/123456789/123456789          # Too long 
curl -v http://ip.ptsang.net/.js      # Too short
curl -v http://ip.ptsang.net/m123/    # DIR
curl -v http://ip.ptsang.net/baba.jpg # non-js
curl -v http://ip.ptsang.net/ga.js    # Ends with .js
curl -v http://ip.ptsang.net/ga.js?t=mmnn # Ends with .js


