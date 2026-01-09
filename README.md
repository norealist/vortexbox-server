**VortexBox Server** - это сервер, относящийся к проекту [VortexBox](https://github.com/norealist/vortexbox)


### Запуск
1. Установите библиотеки:
    * fastapi
    * fastapi-limiter
    * redis
    * uvicorn
    * python-multipart

2. Установите [**redis**](https://timeweb.cloud/tutorials/redis/ustanovka-i-nastrojka-redis-dlya-raznyh-os)

3. Запустите server.py из командной строки:
    * без установки ssl
        ```cmd
        python server.py [ip] [port]
        ```
    * запуск с ssl
        ```cmd
        python server.py [ip] [port] --ssl-public-key /path/to/public/key --ssl-private-key /path/to/private/key
        ```
4. Чтобы остановить сервер, жмите `Ctrl + C`