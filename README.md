
Скрипт для формирования БД реестра запрещенных сайтов. БД может использоваться для работы фильтра запрещённых 
сайтов https://github.com/max197616/extfilter и https://github.com/max197616/nfqfilter.

Данный скрипт основан на https://github.com/max197616/zapret. 

Использование:

zapret.pl - LoginNewURL PasswdNewUrl

zapret.conf [url] - LoginNewURL PasswdNewUrl

Добавлена поддержка проверки sha1 отпечатка сертификата и проверки подписи файлов.

Вытащить sha1 отпечаток из сертификата:
/usr/local/gostopenssl/bin/openssl pkcs7 -in dump_delta.xml.sig -print_certs -inform DER > rkn-ky.pem &&
/usr/local/gostopenssl/bin/openssl x509 -in rkn-ky.pem -sha1 -fingerprint -noout

Проверка на валидность сертификата РКН (вытащить и убедиться в валидности подписи на Госуслуги, можно не делать процедуру)