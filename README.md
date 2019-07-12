# nginx_module_ratelimiter

a nignx http module that limits request number

## precondition

download the nginx source code

## configure

    # git clone this repo
    # go to the nginx source code folder
    # specify this repo path of your system
    ./configure --add-module=/home/sky/code/nginx_module_ratelimiter

## build

    make && make install

## nginx.conf

    # add below ratelimiter option into http section:ratelimiter [expired time(ms)] [slab size(m/k/g)]
    http {
        ....
        ratelimiter 500 10m; 
        ....
    }
    # expired time means all requests have a expired time,when there is a unexpired request,a same request is coming, this new request will be dropped and return 403.
    # slab size represets the total memory that store the all unexpired requests, 
    # if this memory is run out, the nginx will drop the following requests and return 403.
    # if the requests in slab memory expire, the memory will be released and treats the new requests again.

## test

    ./nginx

open http://localhost , you will see the `403 Forbidden` in the browser when you refresh the same page many times during 500ms

## reference

[深入理解Nginx（第2版）](https://book.douban.com/subject/26745255/)
