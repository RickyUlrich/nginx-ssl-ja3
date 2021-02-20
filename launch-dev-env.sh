#!/bin/bash

echo -e 'TO COMPILE RUN:\n    cd nginx\n    ASAN_OPTIONS=symbolize=1 ./auto/configure --add-module=/build/nginx-ssl-ja3 --with-http_ssl_module --with-stream_ssl_module --with-debug --with-stream --with-cc-opt="-fsanitize=address -O -fno-omit-frame-pointer --std=gnu++20 -Wno-error" --with-ld-opt="-L/usr/local/lib -Wl,-E -lasan -lstdc++ -lfmt"\n    make install'

sudo docker run -it -p 443:443 -v $PWD:/build/nginx-ssl-ja3 nginx_ja3
