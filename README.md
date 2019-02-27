# nginx_module_ratelimiter

a module can limit the duplicate request amount in some interval

## precondition

download the nginx source code

## configure

    # specify this repo path of your system
    ./configure --add-module=/home/sky/code/nginx_module_ratelimiter

## build

    make && make install

## nginx.conf

    # add below option into http section, this option means rate limit in 500ms and the slab size is 10mb
    http {
        ....
        ratelimiter 500 10m; 
        ....
    }
    # the slab size means the capacity of the requests in interval,
    # if this memory is run out, nginx would block the other requests until the interval ends.

## test

    ./nginx

open http://localhost , you will see the `403 Forbidden` in the browser when you refresh the same page many times during 500ms
