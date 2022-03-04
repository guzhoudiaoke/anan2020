# PostgreSQL debug

```sh

tar xvf postgresql-14.2.tar.gz
cd postgresql-14.2

./configure --enable-debug --enable-cassert CFLAGS="-ggdb -Og -g3 -fno-omit-frame-pointer" --prefix=/home/liuruyi/postgreSQL
bear -- make
sudo make install

initdb -D ~/postgreSQL/data
pg_ctl -D /home/liuruyi/postgreSQL/data -l logfile start
createdb test
psql test

ps -ef | grep post
sudo gdb -p 19480

```
