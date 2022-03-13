VPN

Схема аналогична работе https://antizapret.prostovpn.org/ (https://bitbucket.org/anticensority/antizapret-vpn-container/src/master/)

Для установки на VPS - `docker-compuse up -d` (требуются дополнительные тесты на разных ОС, проверялось на ubuntu 20.04)

Для установки прозрачного прокси на keenetic роутер:

1. Установить opkg и ndm

2. Скопировать файл `keenetic/opt/etc/ndm/ifstatechanged.d/wg-trsp.sh` из репозитория в `/opt/etc/ndm/ifstatechanged.d/wg-trsp.sh` opkg раздела. Он позволит перенаправлять DNS запросы к внутреннему резолверу при включении интерфейса и убирать перенаправление при его выключении.

3. Сконфигурировать wireguard клиента в web интерфейсе роутера, где приватный ключ (для peer1) - `/opt/wireguard/config/peer1/privatekey-peer1`, публичный ключ сервера - `/opt/wireguard/config/server/publickey-server`. Адрес - `10.224.0.2/15`.

