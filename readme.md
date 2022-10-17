# Клиент сервиса авторизации

### Описание

В комментах используются ссылки на полный сценарий
#### Полный сценарий
1. Отправить на сервис авторизации запрос на получение кода авторизации. При этом передаём state
2. Получить от сервиса авториации 
    - код авторизации (грант, или разрешение, на получение токена). 
    - код state (проверяем: должен совпасть с переданным в п.1)
3. На сервисе авторизации:
    - передать грант - код авторизации из п.2
    - получить в ответе токен доступа (access_token)
    - получить в ответе токен обновления (refresh_token - грант, или разрешение, на обновление токена доступа)
4. Используем токен доступа для доступа к ресурсам сервиса авторизации

Например: запрашиваем информацию о пользователе-владельце токена доступа

5. При истечении срока действия токена запросить новый на сервисе авторизации:
    - передать грант - токен обновления из п. 3.3
получить в ответе 
    - новый токен доступа
    - новый грант - токен обновления



### Установка
- clone
- pip install -r requirements.txt
- pip install -e src
