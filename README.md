A JWT-based authentification system for unofficial INSA Rouen's services.

## Put an entire static website behind auth using nginx

```nginx
server {
    listen 443 ssl;
    listen [::]:443 ssl;

    server_name {{ insa_scan_domains | join(' ') }};

    ssl_certificate /etc/letsencrypt/live/{{ webserver_name }}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{{ webserver_name }}/privkey.pem;

    root /data/insa_scan/site;
    auth_request /auth;
    
    location = /auth {
        internal;
        proxy_pass https://auth.insa.lol/verify;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Original-URI $request_uri;
    }

    error_page 401 = @error401;
    location @error401 {
        return 302 https://auth.insa.lol/login?next=$scheme://$http_host$request_uri;
    }
}
```

## Put a specific scope behind auth using nginx

```nginx
server {
    listen 443 ssl;
    listen [::]:443 ssl;

    server_name {{ insa_scan_domains | join(' ') }};

    ssl_certificate /etc/letsencrypt/live/{{ webserver_name }}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{{ webserver_name }}/privkey.pem;

    root /data/insa_scan/site;
    
    location /private/ {
        auth_request /auth;
        auth_request_set $auth_status $upstream_status;

        auth_request_set $insa_auth_email $upstream_http_x_insa_auth_email;
        auth_request_set $insa_auth_uid $upstream_http_x_insa_auth_uid;
        auth_request_set $insa_auth_uid_number $upstream_http_x_insa_auth_uid_number;
        auth_request_set $insa_auth_groups $upstream_http_x_insa_auth_groups;
        auth_request_set $insa_auth_given_name $upstream_http_x_insa_auth_given_name;
        auth_request_set $insa_auth_family_name $upstream_http_x_insa_auth_family_name;
        proxy_set_header X-Insa-Auth-Email $insa_auth_email;
        proxy_set_header X-Insa-Auth-Uid $insa_auth_uid;
        proxy_set_header X-Insa-Auth-Uid-Number $insa_auth_uid_number;
        proxy_set_header X-Insa-Auth-Groups $insa_auth_groups;
        proxy_set_header X-Insa-Auth-Given-Name $insa_auth_given_name;
        proxy_set_header X-Insa-Auth-Family-Name $insa_auth_family_name;
    }

    location = /auth {
        internal;
        proxy_pass https://auth.insa.lol/verify;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Original-URI $request_uri;
    }

    error_page 401 = @error401;
    location @error401 {
        return 302 https://auth.insa.lol/login?next=$scheme://$http_host$request_uri;
    }
}
```
