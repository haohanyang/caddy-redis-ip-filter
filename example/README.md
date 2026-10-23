# Example

1. Build caddy with plugin

```
xcaddy build --with github.com/haohanyang/caddy-redis-ip-filter=.
```

2. Start redis in docker

```
docker run -d --name redis-test -p 6379:6379 redis
```

3. Run caddy with [Caddyfile](/example/Caddyfile)

```
.\caddy.exe run --config example\Caddyfile
```

4. Test it in another terminal.

```sh
# Neither key exists yet
curl.exe -i http://127.0.0.1:8080   # 403: allow list is empty
curl.exe -i http://127.0.0.1:8081   # 200: deny list is empty

# Add yourself to both lists, then wait about 5s for the reload
docker exec redis-test redis-cli SADD test:allowlist 127.0.0.1 ::1
docker exec redis-test redis-cli SADD test:denylist 127.0.0.1 ::1

curl.exe -i http://127.0.0.1:8080   # 200
curl.exe -i http://127.0.0.1:8081   # 403

# Try the other key types: a string with a range, and a list
docker exec redis-test redis-cli DEL test:allowlist
docker exec redis-test redis-cli SET test:allowlist "10.0.0.0/8, 127.0.0.0/8"
docker exec redis-test redis-cli DEL test:denylist
docker exec redis-test redis-cli RPUSH test:denylist 192.0.2.1
```
