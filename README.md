# stig-manager-with-evaluate-stig
STIG-Manager is useful, Evaluate-STIG is useful, not everyone has an environment to run these the "correct" way, in fact most probably don't (legacy systems, disconnected labs etc...).
This is a guide to deploy STIG-Manager and its dependencies on a single RHEL 8/9 host, be able to use the application from any host that can reach the server, not just localhost, and have the Evaluate-STIG tool upload results directly to it. Nearly all commands are direct copy/pastable, one could probably put this all in a giant script if they were inclined to do so.  

To be clear this is not an official or approved way, just a way that works and will hopefully be useful to people!

## Initial Setup / Prereq's
RHEL 9.4 Minimal Server install w/ DISA Profile applied at install.  Note that RHEL 9.4+ is FIPS 140-3 but Keycloak is only going to be 140-2. This causes some complications later with extracting a key, you will need to do that on a RHEL 8.10 (or other FIPS 140-2) host or you can substitute RHEL 9.4 with RHEL 8.10 and this guide should still be applicable with no changes, just make sure 'alternatives --config java' is ran and openjdk 17 is selected in RHEL 8 if you have more then one version of openjdk installed.

FIPS you are the best! Some FIPS info regarding the above:
- https://access.redhat.com/discussions/7034117  
- https://github.com/keycloak/keycloak/issues/30415  
- https://github.com/keycloak/keycloak/discussions/15971  

Red Hat build of Keycloak
- https://access.redhat.com/products/red-hat-build-of-keycloak

Keycloak used:
- rhbk-24.0.6.zip

FIPS modules for Keycloak (Please keycloak move to the recently released "2.0" 140-3 bouncycastle modules!)
- https://docs.redhat.com/en/documentation/red_hat_build_of_keycloak/24.0/html/server_guide/fips-#fips-bouncycastle-library
- https://www.bouncycastle.org/download/bouncy-castle-java-fips/#latest

FIPS modules Used:
- bc-fips-1.0.2.4.jar 
- bcpkix-fips-1.0.7.jar 
- bctls-fips-1.0.19.jar 

Files stored in ~/

All Commands are ran in a root shell unless noted, you can run as a regular user with sudo if you enjoy typing out your password a lot, or add NOPASSWD temporarily to the sudoers file.

## Install Dependencies
```
dnf install -y mysql-server java-17-openjdk-headless nginx podman podman-docker unzip
```

Get most recent docker-compose from the below link and place it in ~/  
https://download.docker.com/linux/rhel/9/x86_64/stable/Packages/

```
dnf install docker-compose*.rpm
```

Create directory structure.
```
mkdir -p /opt/ca/keys /opt/ca/certs /opt/podman/stigman /opt/keycloak /etc/pki/nginx
chmod 755 /opt/podman
```

### Fapolicyd
Still having a hard time with fapolicyd and podman, so we just disable it.  Some sample rules are provided below, the keycloak one works fine but podman not so much, nor does it trigger anything when running 'fapolicyd --debug-deny' and looking at logs so I'm not really sure what is preventing podman from working with fapolicyd.
```
systemctl stop fapolicyd
systemctl disable fapolicyd
```

Ruleset that appears to work but podman compose up/down still fails, help?
```
echo 'allow perm=open trust=1 : dir=/opt/keycloak/ ftype=application/java-archive trust=0' > /etc/fapolicyd/rules.d/35-keycloak.rules
echo 'allow perm=open trust=0 : dir=/usr/lib64 ftype=application/x-sharedlib trust=1' > /etc/fapolicyd/rules/25-podman.rules
fagenrules --load
systemctl restart fapolicyd
```

## Create a Root CA and Setup Certificates
Make a generic CA, you will need to import the cert into trust stores of all clients, if you have a company or gov CA you can leverage, best to use that and this step is not required - it is also totally insecure for a production environment, whats a CP/CPS???
```
openssl req -x509 -sha256 -days 3650 -nodes -newkey rsa:4096 -subj "/CN=ca.`hostname -d`/C=US/ST=VA/L=CITY/" -keyout /opt/ca/keys/rootCA.key -out /opt/ca/certs/rootCA.crt
trust anchor --store /opt/ca/certs/rootCA.crt
```
Again make sure import rootCA.crt into the, in Windows terms, Local Machine Trusted Root store, of any clients that need to access the web interface of STIG-Manager or that will be running Evaluate-STIG and need to send results to STIG-Manager.

Config files used with openssl, adjust to how many alt names/ip address you have, my test system is dual stack so IP1 = IPv6 address, IP2 = IPv4 address.

CSR Config:
```
cat <<EOF > /opt/ca/csr.conf
[ req ]
default_bits = 2048
prompt = no
default_md = sha256
req_extensions = req_ext
distinguished_name = dn

[ dn ]
C = US
ST = VA
L = CITY
O = ORG
CN = `hostname -f`

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ] 
DNS.1 = `hostname -f`
DNS.2 = `hostname`
IP.1 = `hostname -i | awk '{print $1}'`
IP.2 = `hostname -i | awk '{print $2}'`
EOF
```

Certificate config:
```
cat <<EOF > /opt/ca/cert.conf
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = `hostname -f`
DNS.2 = `hostname`
IP.1 = `hostname -i | awk '{print $1}'`
IP.2 = `hostname -i | awk '{print $2}'`
EOF
```

Create a key and CSR.
```
openssl genrsa -out /opt/ca/keys/`hostname -f`.key 2048
openssl req -new -key /opt/ca/keys/`hostname -f`.key -out /opt/ca/keys/`hostname -f`.csr -config /opt/ca/csr.conf
```

Sign the CSR, if you are using a company or gov CA, sign the CSR with that instead and skip this step.
```
openssl x509 -req -in /opt/ca/keys/`hostname -f`.csr -CA /opt/ca/certs/rootCA.crt -CAkey /opt/ca/keys/rootCA.key -CACreateserial -out /opt/ca/certs/`hostname -f`.crt -days 365 -sha256 -extfile /opt/ca/cert.conf
```
Note that because there is no OCSP / CRL endpoint designated in the certificate (or you are in a disconnected environment with no network path to company/gov) if you use Edge and have it configured to the STIG you need to make an adjustment for #V-235747.  
    
Note #2 we will be using the same certificate for Keycloak + Nginx as they are on the same server (and any other services you might run on it, e.g. can use the same cert within ACAS) and same fqdn to access both, if these are running on separate systems or you want certs for separate hostnames, then create additional as required.

## Nginx Configuration

Place certs where Nginx config can access them.
```
cp /opt/ca/certs/`hostname -f`.crt /etc/pki/nginx/
cp /opt/ca/keys/`hostname -f`.key /etc/pki/nginx/
```

Make proxypass work with SELinux.
```
setsebool -P httpd_can_network_connect 1
```

Nginx Config:
```
cat <<EOF > /etc/nginx/conf.d/stigman.conf
server {
	listen		443 ssl http2;
	listen		[::]:443 ssl http2;
	server_name	`hostname -f`;
	ssl_certificate "/etc/pki/nginx/`hostname -f`.crt";
	ssl_certificate_key "/etc/pki/nginx/`hostname -f`.key";
	client_max_body_size 1024M;
	location / 
	{
		proxy_pass http://127.0.0.1:54000/;
		proxy_set_header Host \$host;
		proxy_set_header X-Forwarded-Server \$host;
		proxy_set_header X-Real-IP \$remote_addr;
		proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
		proxy_set_header X-Forwarded-Host \$host;
		proxy_set_header X-Forwarded-Proto \$scheme;
		proxy_set_header X-Forwarded-Port \$server_port;
	}
}
EOF
```

Check nginx config, if an error e.g. not using IPv6, remove line 3.
```
nginx -t
```
Enable & Start nginx.
```
systemctl enable --now nginx
```

Add Firewall rules.
```
firewall-cmd --permanent --add-port={80/tcp,443/tcp,8443/tcp}
firewall-cmd --reload
```
We will run keycloak and make it directly accessable on :8443, if you wanted run both stigman / keycloak on only :443 you can add different locations in the nginx config and do not need to open tcp/8443. 
  
By default we will also get the default RHEL Nginx works! page on the non-https, http://your-stigman-fqdn, this should be disabled and 80 redirected to 443 by editing /etc/nginx/nginx.conf, placing this in the server block for port 80, `return 301 https://$host$request_uri;` and removing the `root path`.
  
At this point from a client machine you should be able to go to https://your-stigman-fqdn/ and get a "Nginx 502 Bad Gateway" error. This at least tells you its up and running and your certificate is trusted, if you get a certificate error then something was skipped above.

## MySQL Setup
We are using the default configuration as installed by Red Hat, you will need to apply the STIG still.
  
Fixes for warning in keycloak.
```
echo 'sort_buffer_size=128M' >> /etc/my.cnf.d/mysql-server.cnf
echo 'innodb_buffer_pool_size=512M' >> /etc/my.cnf.d/mysql-server.cnf
```

Start it up.
```
systemctl enable --now mysqld
mysql -u root
```
At the `mysql>` prompt enter the following:
```
CREATE DATABASE stigman CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
CREATE USER 'stigman'@'%' IDENTIFIED BY 'stigmanpassword';
GRANT ALL ON stigman.* to 'stigman';

CREATE DATABASE keycloak CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
CREATE USER 'keycloak'@'%' IDENTIFIED BY 'keycloakpassword';
GRANT ALL ON keycloak.* TO 'keycloak';
GRANT XA_RECOVER_ADMIN on *.* to 'keycloak';

FLUSH PRIVILEGES;
exit
```

XA_RECOVER permissions fixes another keycloak warning (all or none on the server, can't grant to individual databases), it likely is excessive permissions but the only thing running in the database is is stigman & keycloak and if you can already control the keycloak database you can give permissions though the application to control stigman anyways.

## Account Setup
Create some low privilege accounts, may be able to change to nologin later (not tested) Also remove password change requirements, have the SA change IAW local schedule as no one likes their application account to randomly stop working because someone forgot to change a password before it expired.
```
useradd -u 10000 -m svc-keycloak
useradd -u 10001 -m svc-stigman
chage -m -1 -M -1 svc-keycloak
chage -m -1 -M -1 svc-stigman
```

Set an initial password.
```
passwd svc-keycloak
passwd svc-stigman
```

## Keycloak Setup
### Initial Application Setup
Extract RH Keycloak, setup FIPS modules and certificates.
```
unzip ~/rhbk-24.0.6.zip -d /opt/keycloak/
ln -s /opt/keycloak/rhbk-24.0.6/ /opt/kc
cp ~/bc*.jar /opt/kc/providers
cp /opt/ca/keys/`hostname -f`.key /opt/kc/conf
cp /opt/ca/certs/`hostname -f`.crt /opt/kc/conf
```

Create necessary config files.
```
mv /opt/kc/conf/keycloak.conf /opt/kc/conf/keycloak.conf.orig
echo 'quarkus.transaction-manager.enable-recovery=true' > /opt/kc/conf/quarkus.properties
echo 'securerandom.strongAlgorithms=PKCS11:SunPKCS11-NSS-FIPS' > /opt/kc/conf/kc.java.security

cat <<EOF > /opt/kc/conf/keycloak.conf
db=mysql
db-username=keycloak
db-password=keycloakpassword
db-url-host=127.0.0.1
https-certificate-file=/opt/kc/conf/`hostname -f`.crt
https-certificate-key-file=/opt/kc/conf/`hostname -f`.key
hostname=`hostname -f`
hostname-strict-backchannel=true
https-key-store-password=keystorepassword
log-level=INFO
#Uncomment For Debugging
#log-level=INFO,org.keycloak.common.crypto:TRACE,org.keycloak.crypto:TRACE
EOF
```

Set permissions to the unprivileged user and login as them.
```
chown -R svc-keycloak:svc-keycloak /opt/keycloak
su - svc-keycloak
```

Generate initial keystore, unsure if they is truely necessary, I think I had it running with it without it at some point but is in the Red Hat documentation.
```
keytool -genkeypair -sigalg SHA512withRSA -keyalg RSA -storepass passwordpassword \
  -keystore /opt/kc/conf/server.keystore \
  -alias localhost \
  -dname CN=localhost -keypass passwordpassword
```

"Build" Keycloak configuration with FIPS enabled, a bunch of warning will go by, you can ignore them.
```
/opt/kc/bin/./kc.sh build --features=fips
```

Set default credentials since it is running on a headless box.
```
export KEYCLOAK_ADMIN=admin
export KEYCLOAK_ADMIN_PASSWORD=adminpassword
```

Start it up, first time will take a while as it populates the mysql database.
```
/opt/kc/bin/./kc.sh start --optimized -Djava.security.properties=/opt/kc/conf/kc.java.security
```

Broswe to https://your-stigman-fqdn:8443  
Login, change your admin password to something better. Ctrl+c in the terminal to shut it down and leave svc-keycloak account, back to root.
```
ctrl+c
exit
```

Startup Keycloak at boot.
```
cat <<EOF > /etc/systemd/system/keycloak.service
[Unit]
Description=keycloak
DefaultDependencies=no
Requires=mysqld.service
After=mysqld.service

[Service]
Type=simple
User=svc-keycloak
Group=svc-keycloak
WorkingDirectory=/opt/kc/bin
ExecStart=/bin/bash /opt/kc/bin/kc.sh start --optimized -Djava.security.properties=/opt/kc/conf/kc.java.security
TimeoutStartSec=0
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl enable --now keycloak
```
You should be able to go back and hit the web interface again.

### STIGMan Realm Setup
Create a new realm, import this file rather then typing everything out according to the STIG-Manager docs.
- https://github.com/NUWCDIVNPT/stig-manager-auth/blob/main/import_realm.json

Change settings to the following in the STIG Manager realm.
```
Realm Settings->General->Require SSL: All (External Requests also works)
Realm Settings->Events, enable both user & admin events for a period consistent with your environment
```

x509 auth flow is configured by default in the imported realm, but keycloak errors out in this setup becuase of it, you cannot even click on it to view the settings. You cannot auth to stigman until this is fixed. The solution is to bind the default browser flow which will unbind the x509 one.
```
Authentication->Browser->Action->Bind Flow
```
If you require this (assume related to CAC auth), you'll have to figure this out, perhaps recreating it will work or keycloak needs some additional module installed first?
  
Create your initial admin user in the stigman realm that you will login to the web interface with, assign admin & user roles.

## Podman Setup
Copy rootCA in, must be world readable to work within the stig-manager container!
```
cp /opt/ca/certs/rootCA.crt /opt/podman/stigman
chmod 644 /opt/podman/stigman/rootCA.crt
```

Docker compose file for STIG-Manager.
```
cat <<EOF > /opt/podman/stigman/docker-compose.yml
networks:
  default:
    name: stigman
    external: false
services:
  stigman:
    image: nuwcdivnpt/stig-manager:1.4.13
    ports:
      - 54000:54000
    environment:
      - STIGMAN_OIDC_PROVIDER=https://`hostname -f`:8443/realms/stigman
      - STIGMAN_CLIENT_OIDC_PROVIDER=https://`hostname -f`:8443/realms/stigman
      - STIGMAN_CLASSIFICATION=U
      - STIGMAN_DB_HOST=`hostname -f`
      - STIGMAN_DB_USER=stigman
      - STIGMAN_DB_PASSWORD=stigmanpassword
      - NODE_EXTRA_CA_CERTS=/home/node/rootCA.crt
    volumes:
      - /opt/podman/stigman/rootCA.crt:/home/node/rootCA.crt
    init: true
EOF
```

Change permissions on everything.
```
chown -R svc-stigman:svc-stigman /opt/podman/stigman
```

Rootless containers are a good thing.
```
sed -i -e 's/^user.max_user_namespaces = 0/user.max_user_namespaces = 10000/' /etc/sysctl.d/99-sysctl.conf
sysctl -p /etc/sysctl.d/99-sysctl.conf
systemctl enable --now podman
```

Ssh in as svc-stigman (su - svc-stigman will not work) to avoid initial podman warnings about cgroups and systemd and enable the user socket.
```
systemctl --user enable --now podman.socket
```

Either podman pull nuwcdivnpt/stig-manager:1.4.13 (or later) direct on this host if possible or pull it on a connected host, save the image to a tar file, transfer it to this server and then load the image into podman.
```
cd /opt/podman/stigman
podman compose up
```

Note I rebooted here just to make sure everything was up and running correctly when I was having issued with fapolicyd before turning it off, if podman does not work yet, reboot!  

STIG-Manager will take a minute to startup as it populates the database, you should see no warnings regarding `NODE_EXTRA_CA_CERTS`, if you do fix it.  
The final messages should look like this:
```
stigman-1  | {"date":"2024-09-03T23:22:02.169Z","level":3,"component":"index","type":"listening","data":{"port":54000,"api":"/api","client":"/","documentation":"/docs"}}
stigman-1  | {"date":"2024-09-03T23:22:04.106Z","level":3,"component":"mysql","type":"preflight","data":{"success":true,"version":"8.0.36"}}
stigman-1  | {"date":"2024-09-03T23:22:04.134Z","level":3,"component":"mysql","type":"migration","data":{"message":"MySQL schema is up to date"}}
stigman-1  | {"date":"2024-09-03T23:22:04.354Z","level":3,"component":"oidc","type":"discovery","data":{"success":true,"metadataUri":"https://your-stigman-fqdn:8443/realms/stigman/.well-known/openid-configuration","jwksUri":"https://your-stigman-fqdn:8443/realms/stigman/protocol/openid-connect/certs"}}
stigman-1  | {"date":"2024-09-03T23:22:04.360Z","level":3,"component":"index","type":"started","data":{"durationS":4.854736624}}
```

Stop it so we can auto start it with systemd.
```
ctrl+z
podman compose down
exit
```

Make sure you are back to a root terminal.
```
cat <<EOF > /etc/systemd/system/stigman.service
[Unit]
Description=STIG-Manager
Requires=keycloak.service
After=keycloak.service

[Service]
user=svc-stigman
group=svc-stigman
TimeoutStopSec=15
WorkingDirectory=/opt/podman/stigman
ExecStartPre=podman compose -f docker-compose.yml down
ExecStart=podman compose -f docker-compose.yml up
ExecStop=podman compose -f docker-compose.yml down

[Install]
WantedBy=multi-user.target
EOF

systemctl enable --now stigman
```
## STIG-Manager Complete
The server is now complete with a functioning instance if STIG-Manager which you can login with a username/password, reboot and make sure everything comes up and you can move around the application as a regular user.

## Evaluate-STIG & Auto Uploading
Credit to C. R., ISSE, 39th IOS/DOS, as most of this part of the guide was taken from the STIG-Manager guide included with ES 1.2407.0 but there are a few changes.

### Create/Configure a Keycloak Client

Configure the Keycloak Client
- Login to Keycloak as an administrator.
- Change the Realm drop-down to the STIG Manager realm.
- From the realm management pane on the left, select Clients.
- Click the Create client button.
- Set the Client type to OpenID Connect.
- Set the Client ID to "evaluatestig".
- Click Next.
- Enable the Client Authentication switch.
- Leave the Authorization switch disabled.
- Uncheck all authentication flows.
- Check the box for Service account roles.
- Click Next.
- Leave Root URL and Home URL empty.
- Click Save.

Configure Service Account Roles
- From the evaluatestig Client details window, select the Service account roles tab.
- Click the Assign Role button.
- Check the box for the user role.
- Click the Assign button.

Configure Client Scopes
- Next, from the Client scopes tab, click the button Add client scope.
- Add the following client scopes:

  - stig-manager:collection   Default
  - stig-manager:stig:read    Default
  - stig-manager:user:read    Default

Credentials
- Select the Credentials tab.
- For Client Authenticator select Signed JWT.
- For Signature algorithm select RS256.
- Click Save.
- A prompt may appear confirming Change to client-jwt? Select Yes.


Keys
- Select the Keys tab.
- Leave the Use JWKS URL switch set to disabled.
- Click the Generate new keys button.
- Select PKCS12 for the Archive format.
- Set Key alias to evaluatestig.
- Set Key password - "passwordpassword" This password will be required in a later step.
- Set Store password - "passwordpassword" This password will be required in a later step.
- Passwords must be at least 14 characters long.
- Click the Generate button.
- Save the keystore.p12 file


### Configure Evaluate-STIG
Back to the FIPS issue from the start of this guide, this is where it shows up and I do not know how to force Keycloak to use a different algorithm for the RSA signature. Transfer the keystore.p12 file to a RHEL 8.10 host (or any host thats FIPS 140-2, as long as its not 140-3!) so we can extract the key

What happens on RHEL9.4 in FIPS mode
```
[randoms7ring@security ~]$ openssl pkcs12 -nodes -in keystore.p12 -out es.cert.pem
Enter Import Password:
Error outputting keys and certificates
808B95C2C97F0000:error:0308010C:digital envelope routines:inner_evp_generic_fetch:unsupported:crypto/evp/evp_fetch.c:373:Global default library context, Algorithm (DES-EDE3-CBC : 27), Properties ()
[randoms7ring@security ~]$
```

From a FIPS 140-2 host this will be sucessful and output 'es.cert.pem' in your current working directory.
```
openssl pkcs12 -nodes -in keystore.p12 -out es.cert.pem
```

Copy es.cert.pem to your ES directory
Edit preferences.xml in ES directory, replace SMImport_COLLECTION Name="" with your collection name.  Set collection ID to the ID of that name.
```
  <STIGManager>
    <SMImport_API_BASE>https://your-stigman-fqdn/api</SMImport_API_BASE>
    <SMImport_AUTHORITY>https://your-stigman-fqdn:8443/realms/stigman</SMImport_AUTHORITY>
    <SMImport_COLLECTION Name="Test">
      <SMImport_CLIENT_ID>evaluatestig</SMImport_CLIENT_ID>
      <SMImport_CLIENT_CERT>C:\users\randoms7ring\Documents\Evaluate-STIG\es.cert.pem</SMImport_CLIENT_CERT>
      <SMImport_CLIENT_CERT_KEY></SMImport_CLIENT_CERT_KEY>
      <SMImport_COLLECTION_ID>1</SMImport_COLLECTION_ID>
    </SMImport_COLLECTION>
  </STIGManager>
```

Pre-register Keycloak Client in STIG-Manager
- Sign-in to STIG-Manager as an administrator.
- From the navigation pane on the left, expand Application Management then select User Grants.
- On the User Grants window, click the Pre-register User button.
- In the Username field enter the Client ID created in Keycloak previously, "evaluatestig".
- Now click the New Grant button.
- Set the Collection drop-down to the collection that you would like Evaluate-STIG to output results to.
- Set the Access Level drop-down to Manage.
- Click the Save button


### Test with Evaluate-STIG
Run Evaluate-STIG (Meet all pre-reqs such as imported DoD certs first), PowerShell 7.4.5 was used in this environment.
.\Evaluate-STIG.ps1 -ComputerName sometarget.fqdn -ScanType Unclassified -Output STIGManager -SMCollection "Test"

Output in ES should end with something similiar, then go see the results in STIG-Manager!
```
Uploading to STIG Manager...
  Processing 715 Vulnerabilities...
    Attempting upload of 715 Reviews...
Done!
Total Time : 00:01:44.1861733
```

## Conclusion
You should now have a a more automated work flow and be able to leverage the capabilities of STIG-Manager and Evaluate-STIG together at last.

If you find an error with this guide, please let me know, I may have typo'd something or what I said/described only makes sense in my own head.  Pictures for the Keycloak GUI part would probably be helpful, I may get around to that later. If there is a better way to do something, I am open to suggestions.
