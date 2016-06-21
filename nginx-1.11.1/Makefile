
default:	build

clean:
	rm -rf Makefile objs

build:
	$(MAKE) -f objs/Makefile

install:
	$(MAKE) -f objs/Makefile install

modules:
	$(MAKE) -f objs/Makefile modules

upgrade:
	/home/lancelot/nginx//nginx -t

	kill -USR2 `cat /home/lancelot/nginx//nginx.pid`
	sleep 1
	test -f /home/lancelot/nginx//nginx.pid.oldbin

	kill -QUIT `cat /home/lancelot/nginx//nginx.pid.oldbin`
