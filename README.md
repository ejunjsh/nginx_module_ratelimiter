# nginx_module_ratelimiter
a module can limit the duplicate request numbers

## precondition

download the nginx source code

## configure

    # specify this repo path of your system
    ./configure --add-module=/home/sky/code/nginx_module_ratelimiter

## build

    make && make install

## nginx.conf

    # add below option into http section, this option means rate limit in 1s and the slab size is 10mb
    ratelimiter 1 10m;

## test

    ./nginx

you will see the 403 Forbidden in the browser when you refresh the page many times during 1s