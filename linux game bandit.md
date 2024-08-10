# linux game bandit

lv0:host is [**bandit.labs.overthewire.org](http://bandit.labs.overthewire.org), on the port 2220. The username is bandit0 and the password is also bandit0.**

lv0→lv1: Firstly use `ls` to find the readme, and `cat readme` to get the password(ZjLjTmM6FvvyRnrb2rfNWOZOTa6ip5If), use this password to login. The new username is bandit1, the port stays the same.

lv1→lv2: The filename is “-”, open it use “cat ./-”, password is 263JGJPfgU6LtdEvgfWU1XP5yac29mFx and the username is bandit2

lv2→lv3. The filename has space which is “spaces in this filename”. To open the filename with space, you can do (cat "file name with spaces”), (cat file\ name\ with\ spaces) or (cat 'file name with spaces’) and the password is MNk8KNH3Usiio41PRUEoDFPqfxLPlSmx, the username is bandit3

lv3→lv4. The password for the next level is stored in a hidden file in the inhere directory. Firstly use “ls -a” to get all the hidden file(**Find the hidden file**: Look for a file that starts with a dot (`.`). This is a common convention for hidden files in Linux. For example, the file might be named `.hiddenfile` or `.password`). Then use “cat ...Hiding-From-You”. The password is 2WmrDFRmJIq3IPxneAaMGhap0pFhF3NJ, the username changes to bandit4

lv4→lv5:The password is stored in only human-readale file. Firstly, “cd inhere” and find that the file name is like “-file00”. Using “file ./-file00” can show if it is ASCII text which is human-readable. so we find that the “-/file07” is ASCII text code. The type “cat ./-file07” we can find the password:4oQYVPkxZOOEOO5pTW81FB8j8lxXGUQw

The username is bandit5

lv5→lv6:

The password for the next level is stored in a file somewhere under the **inhere** directory and has all of the following properties:

- human-readable
- 1033 bytes in size
- not executable

use `find . -type f -size 1033c ! -executable -exec file {} + | grep "ASCII text"` then use “cat ./.file2”. So the password is HWasnPhtq9AVKe0dmk45nxy20cvUa6EG.

The username is bandit6

lv6→lv7

The password for the next level is stored **somewhere on the server** and has all of the following properties:

- owned by user bandit7
- owned by group bandit6
- 33 bytes in size

so we still use the command line which is  `find / -type f -user bandit7 -group bandit6 -size 33c 2>/dev/null` then use “cat /var/lib/dpkg/info/bandit7.password”

or

```
find / -type f -user bandit7 -group bandit6 -size 33c 2>/dev/null | xargs cat
```

or

```
find / -type f -user bandit7 -group bandit6 -size 33c 2>/dev/null -exec cat {} +
```

for the 2 in "2>/dev/null”,

for the {} +

The password is morbNTDkSW6jIlUc0ymOdMaLnOlFVAaj

The username for the next is bandit7

lv7→lv8

The password for the next level is stored in the file **data.txt** next to the word **millionth.**

Use the command `grep "millionth" data.txt` to find the line containing the word "millionth" and retrieve the password: dfwvzFQi4mU0wfNbFOe9RoWskMLg7eEc. The username for the next level is bandit8.

lv8→lv9

The password for the next level is stored in the file **data.txt** and is the only line of text that occurs only once. use `sort data.txt | uniq -u` to find the password(4CKMh1JI91bUIZZPXDqGanal4xvAg0JM) username is bandit9

Below is the detailed explanations of sort and uniq

```bash
sort filename.txt#Sort a File Alphabetically
sort -r filename.txt#Sort in Reverse Order
sort filename.txt -o sorted_filename.txt#Sort and Save Output to a File
sort -f filename.txt#Sort with Case Insensitivity
sort -n filename.txt#Sort Numerically
sort -k 2 filename.txt#For example, to sort by the second field (assuming fields are space-separated)
sort -k 2,2 -k 3,3 filename.txt#For example, to sort by the second field and then by the third field
sort -t ',' -k 2 filename.csv#For example, if fields are separated by commas

#as for the uniq
uniq filename.txt#Remove Adjacent Duplicate Lines
uniq -u filename.txt#Print Only Unique Lines
uniq -d filename.txt#Print Duplicate Lines Only
uniq -c filename.txt#Count the Number of Occurrences
uniq -i filename.txt#Ignore Case Differences
uniq -f 1 filename.txt#For example, ignoring the first field and comparing the rest
```

lv9→lv10

The password for the next level is stored in the file data.txt in one of the few human-readable strings, preceded by several ‘=’ characters.

Use the command `strings data.txt | grep "====="`

The password is FGUW5ilLVJrxX9kMYMmlN4MgbpfMiqey The user name is bandit10

```bash
strings filename#Extract Printable Strings from a File
strings -a filename#'-a' or '--all': Scan the entire file, not just the initialized and loaded sections of object files.
strings -n 8 filename#'-n <number>' or '--bytes=<number>': Specify the minimum length of a string to be printed (default is 4).
strings -t d filename#'-t <format>' or '--radix=<format>': Print the location of the string in the file in the specified format (octal, decimal, or hexadecimal)
strings -e s filename#'-e <encoding>' or '--encoding=<encoding>': Specify the character encoding (s, S for single-7-bit-byte characters, b, B for 8-bit, l, L for 16-bit, and u, U for 32-bit).

# Basic usage of grep to search for a pattern in a file
grep "pattern" filename
# Ignore case distinctions in both the pattern and the input files
grep -i "pattern" filename
# Invert the sense of matching, to select non-matching lines
grep -v "pattern" filename
# Recursively search directories
grep -r "pattern" directory
grep -R "pattern" directory
# Print only the names of files with matching lines, separated by newlines
grep -l "pattern" filename
# Print only a count of matching lines per file
grep -c "pattern" filename
# Prefix each line of output with the line number within its input file
grep -n "pattern" filename
# Print the filename for each match
grep -H "pattern" filename
# Interpret the pattern as an extended regular expression (ERE)
grep -E "pattern" filename
# Match only whole words
grep -w "pattern" filename
```

lv10→lv11

The password for the next level is stored in the file **data.txt**, which contains base64 encoded data

use the command line `base64 --decode data.txt`

The password is dtR173fZKb0RRsDFSGsg2RWnpNVj3qRr

The username is bandit11

```bash
# View the contents of a file
cat data.txt

# Encode a file to Base64 and print the result
base64 data.txt

# Decode a Base64 encoded file and print the result
base64 -d encoded.txt

# Encode a file to Base64 and save the result to another file
base64 data.txt -o encoded.txt

# Decode a Base64 encoded file and save the result to another file
base64 -d encoded.txt -o decoded.txt

# Encode a string to Base64
echo -n "Hello, World!" | base64

# Decode a Base64 encoded string
echo "SGVsbG8sIFdvcmxkIQ==" | base64 -d

# Decode a Base64 encoded file with custom wrapping of 0 (no wrapping)
base64 -d -w 0 encoded.txt

# Decode the base64 data in data.txt and print it to the terminal
base64 -d data.txt
```

lv11→lv12

Use the command `cat data.txt | tr 'A-Za-z' 'N-ZA-Mn-za-m'`

The password is 7x16WNeHIi5YkIhWsfFIqoognUTyj9Q4

The username is bandit12

```bash
# Translate characters
tr 'SET1' 'SET2'
# Delete characters
tr -d 'SET1'
# Squeeze characters
tr -s 'SET1'
# Complement characters
tr -c 'SET1' 'SET2'
# Translate lowercase to uppercase
echo "hello world" | tr 'a-z' 'A-Z'
# ROT13 encoding/decoding
echo "hello world" | tr 'A-Za-z' 'N-ZA-Mn-za-m'
# Delete all vowels
echo "hello world" | tr -d 'aeiou'
# Delete all non-digit characters
echo "a1b2c3d4" | tr -d -c '0-9'
# Squeeze multiple spaces into a single space
echo "hello    world" | tr -s ' '
# Squeeze multiple newline characters
echo -e "line1\\n\\nline2\\n\\n\\nline3" | tr -s '\\n'
# Complement: delete all characters except digits
echo "hello123" | tr -d -c '0-9'
# Combine translate and squeeze
echo "aabbcc" | tr 'a-c' 'A-C' | tr -s 'A-C'
# Decode ROT13
cat data.txt | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

lv12→lv13

The password for the next level is stored in the file **data.txt**, which is a hexdump of a file that has been repeatedly compressed. For this level it may be useful to create a directory under /tmp in which you can work. Use mkdir with a hard to guess directory name. Or better, use the command “mktemp -d”. Then copy the datafile using cp, and rename it using mv (read the manpages!)

The password is hidden so deep, so we first follow the instructions to create an empty directory then operate the command lines below until line 8, we repeatedly recognize the file we decompress till we finally get the ASCII text.

```bash
tmp_dir=$(mktemp -d)
echo "Working directory: $tmp_dir"
cd "$tmp_dir"
cp ~/data.txt "$tmp_dir"
mv data.txt hexdump.txt
xxd -r hexdump.txt compressed_file.bin
#identify the file type 
file compressed_file.bin
#if zip 
mv compressed_file.bin compressed_file.gz
gunzip compressed_file.gz
#if bzip2
mv compressed_file.bin compressed_file.bz2
bunzip2 compressed_file.bz2
#if xz
mv compressed_file.bin compressed_file.xz
unxz compressed_file.xz
#if tar
mv compressed_file.bin compressed_file.tar
tar xf compressed_file.tar
#if zip
mv compressed_file.bin compressed_file.zip
unzip compressed_file.zip
```

The username is bandit13

The password is FO5dwFsc0cbaIiH0h8J2eUks2vdTDwAn

lv13→lv14

The password for the next level is stored in **/etc/bandit_pass/bandit14 and can only be read by user bandit14**. For this level, you don’t get the next password, but you get a private SSH key that can be used to log into the next level. **Note:** **localhost** is a hostname that refers to the machine you are working on

They have already provide me the private sshkey to connect to the bandit14

```
ssh -i sshkey.private bandit14@localhost -p 2220
```

The private key:MU4VWeTyJk8ROof1qqmcBPaLh7lDCPvS

username is bandit14

```bash
#Basic connection
ssh username@hostname
#Specifying port
ssh -p port_number username@hostname
#Using a key file
ssh -i /path/to/key_file username@hostname
#SSH Config File
~/.ssh/config
#Port Forwarding:
#Local: 
ssh -L local_port:remote_host:remote_port username@hostname
#Remote: 
ssh -R remote_port:local_host:local_port username@hostname
#File transfer over SSH: 
scp source_file username@hostname:destination_path
#-N: Do not execute a remote command. This is useful for just forwarding ports.
ssh -N -L 8080:localhost:80 user@example.com
#-f: Requests SSH to go to the background just before command execution.
ssh -f -N -L 8080:localhost:80 user@example.com
#-t: Forces pseudo-terminal allocation. This can be used to execute arbitrary screen-based programs on a remote machine.
ssh -t user@example.com 'htop'
```

lv14→lv15

passwrod for this level(like the one we found above just now) MU4VWeTyJk8ROof1qqmcBPaLh7lDCPvS

use the command line `telnet localhost 30000` to connect to the port 30000

then type the password of last level

The username is bandit15

The password for the next level:8xCjnmgoKbGLhHFAZlGE5Tmu4M2tKJQo

```bash
#telnet
#connect use to connect a remote host
telnet hostname port

#nc
nc hostname port
#listen for incoming connection on some port
nc -l -p 5000
#Transfer a file to a remote host on port 5000:
cat file.txt | nc remote_host 5000
#Receive a file from a remote host on port 5000:
nc -l 5000 > received_file.txt
#Scan for open ports on a remote host (TCP ports 22, 80, and 443):
nc -zv remote_host 22 80 443

#openssl
openssl command [options] [arguments]
##Certificate Management:
openssl req: Generate certificate signing requests (CSRs) to obtain certificates from Certificate Authorities (CAs).
openssl x509: Manipulate and examine X.509 certificates.
openssl ca: Act as your own Certificate Authority, signing and issuing certificates.
openssl pkcs12: Package certificates and private keys into PKCS#12 files, commonly used for importing/exporting certificates.
Encryption and Decryption:
openssl enc: Encrypt and decrypt files using various symmetric ciphers like AES, DES, and more.
openssl rsautl: Encrypt and decrypt data using RSA keys.
openssl dgst: Calculate message digests (hashes) using algorithms like SHA-256, MD5, etc.
Key Generation and Management:
openssl genrsa: Generate RSA private keys.
openssl genpkey: Generate various types of keys, including RSA, DSA, and ECDSA.
openssl rsa: Manage RSA keys, including converting between different formats.
SSL/TLS Testing and Troubleshooting:
openssl s_client: Connect to an SSL/TLS server and analyze the connection details, including the certificate chain and supported cipher suites.
openssl s_server: Set up a temporary SSL/TLS server for testing purposes.
Other Utilities:
openssl speed: Benchmark the performance of various cryptographic algorithms.
openssl rand: Generate pseudo-random bytes.
openssl version: Display the OpenSSL version information.
#Generating a private key:
openssl genrsa -out private_key.pem 2048
#encrypt a file 
openssl enc -aes-256-cbc -salt -in input.txt -out output.enc
#decrypt a file 
openssl enc -d -aes-256-cbc -in output.enc -out decrypted.txt
#checking a website's SSL/TLS 
openssl s_client -connect www.example.com:443
```

lv15→lv16

The password for the next level can be retrieved by submitting the password of the current level to **port 30001 on localhost** using SSL/TLS encryption.

`openssl s_client -connect [localhost:30001](<http://localhost:30001>)` and then just type the password 8xCjnmgoKbGLhHFAZlGE5Tmu4M2tKJQo

username:bandit16

password:kSkvUpMQ7lBYyCM4GBPvCvT1BfWRy0Dx

lv16→17

So firstly find the one with server listening to `nmap -p 31000-32000 [localhost](<http://localhost>)`

type `cat /etc/bandit_pass/bandit16` to get the password of this level which is kSkvUpMQ7lBYyCM4GBPvCvT1BfWRy0Dx

then use `ncat --ssl localhost 31790` and type the password we just found, we can get the private key

```bash
----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAvmOkuifmMg6HL2YPIOjon6iWfbp7c3jx34YkYWqUH57SUdyJ
imZzeyGC0gtZPGujUSxiJSWI/oTqexh+cAMTSMlOJf7+BrJObArnxd9Y7YT2bRPQ
Ja6Lzb558YW3FZl87ORiO+rW4LCDCNd2lUvLE/GL2GWyuKN0K5iCd5TbtJzEkQTu
DSt2mcNn4rhAL+JFr56o4T6z8WWAW18BR6yGrMq7Q/kALHYW3OekePQAzL0VUYbW
JGTi65CxbCnzc/w4+mqQyvmzpWtMAzJTzAzQxNbkR2MBGySxDLrjg0LWN6sK7wNX
x0YVztz/zbIkPjfkU1jHS+9EbVNj+D1XFOJuaQIDAQABAoIBABagpxpM1aoLWfvD
KHcj10nqcoBc4oE11aFYQwik7xfW+24pRNuDE6SFthOar69jp5RlLwD1NhPx3iBl
J9nOM8OJ0VToum43UOS8YxF8WwhXriYGnc1sskbwpXOUDc9uX4+UESzH22P29ovd
d8WErY0gPxun8pbJLmxkAtWNhpMvfe0050vk9TL5wqbu9AlbssgTcCXkMQnPw9nC
YNN6DDP2lbcBrvgT9YCNL6C+ZKufD52yOQ9qOkwFTEQpjtF4uNtJom+asvlpmS8A
vLY9r60wYSvmZhNqBUrj7lyCtXMIu1kkd4w7F77k+DjHoAXyxcUp1DGL51sOmama
+TOWWgECgYEA8JtPxP0GRJ+IQkX262jM3dEIkza8ky5moIwUqYdsx0NxHgRRhORT
8c8hAuRBb2G82so8vUHk/fur85OEfc9TncnCY2crpoqsghifKLxrLgtT+qDpfZnx
SatLdt8GfQ85yA7hnWWJ2MxF3NaeSDm75Lsm+tBbAiyc9P2jGRNtMSkCgYEAypHd
HCctNi/FwjulhttFx/rHYKhLidZDFYeiE/v45bN4yFm8x7R/b0iE7KaszX+Exdvt
SghaTdcG0Knyw1bpJVyusavPzpaJMjdJ6tcFhVAbAjm7enCIvGCSx+X3l5SiWg0A
R57hJglezIiVjv3aGwHwvlZvtszK6zV6oXFAu0ECgYAbjo46T4hyP5tJi93V5HDi
Ttiek7xRVxUl+iU7rWkGAXFpMLFteQEsRr7PJ/lemmEY5eTDAFMLy9FL2m9oQWCg
R8VdwSk8r9FGLS+9aKcV5PI/WEKlwgXinB3OhYimtiG2Cg5JCqIZFHxD6MjEGOiu
L8ktHMPvodBwNsSBULpG0QKBgBAplTfC1HOnWiMGOU3KPwYWt0O6CdTkmJOmL8Ni
blh9elyZ9FsGxsgtRBXRsqXuz7wtsQAgLHxbdLq/ZJQ7YfzOKU4ZxEnabvXnvWkU
YOdjHdSOoKvDQNWu6ucyLRAWFuISeXw9a/9p7ftpxm0TSgyvmfLF2MIAEwyzRqaM
77pBAoGAMmjmIJdjp+Ez8duyn3ieo36yrttF5NSsJLAbxFpdlc1gvtGCWW+9Cq0b
dxviW8+TFVEBl1O4f7HVm6EpTscdDxU+bCXWkfjuRb7Dy9GOtt9JPsX8MBTakzh3
vBgsyi/sN3RqRBcGU40fOoZyfAMT8s1m/uYv52O6IgeuZ/ujbjY=
-----END RSA PRIVATE KEY-----
cd /tmp/
touch private.key
ssh -i private.key [bandit17@localhost](<mailto:bandit17@localhost>) -p2220
cat /etc/bandit_pass/bandit17
```

The username is bandit17

The password is EReVavePLFHtFlFsjn3hyzMlvSuSAcRD

lv17→lv18

```
diff [password.new](<http://password.new>) password.old
```

`ssh [bandit18@bandit.labs.overthewire.org](<mailto:bandit18@bandit.labs.overthewire.org>) -p 2220 -t /bin/sh`(this uses sh to login which avoid the bash)

```
ssh -p 2220 [bandit18@bandit.labs.overthewire.org](<mailto:bandit18@bandit.labs.overthewire.org>) "cat readme"
```

(this doesn’t login the server just get the readme file)

to avoid the logout problem

The username is bandit18

The password is x2gLTTjFwMOhQ8oWNbMN362QKxfRqGlO

lv18→lv19

```
cat readme
```

The username is bandit19

The password is cGWpMaKXVwDUNgPAVJbWYuGHVn9zl3j8

lv19→lv20

```
./bandit20-do cat /etc/bandit_pass/bandit20
```

The username is bandit20

The password is 0qXahG8ZjOVMN9Ghs7iOWsCfZyXOUbYO

lv20→lv21

The username is bandit21

The password is EeoULMCra2q0dSkYj561DX7s1CpBuOBt

establish the connection `nc -l -p 12345`

then open another terminal use `./suconnect` type the passwrod we get the answer.

lv21→lv22

```
cd /etc/cron.d
cat cronjob_bandit22
```



This means that Run the `cronjob_bandit22.sh` script at system startup

The five asterisks (`* * * * *`) represent the cron job's schedule, which is set to run every minute (i.e., every 60 seconds). The format is: `minute hour day month day_of_week`.

```
cat /usr/bin/cronjob_bandit22.sh
cat /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
```

The username is bandit22

The password is tRae0UfB9v0UzbCdn9cY0gQnds9GF58Q

lv22→lv23

The username is bandit23

The password is 0Zf11ioIjMVN551jX3CmStKLYqjk54Ga

```
cd /etc/cron.d/
cat cronjob_bandit23
cat /usr/bin/cronjob_bandit23.sh
```



For the default name of `myname` is bandit22 we need to change it into bandit23

```
echo "I am user bandit23" | md5sum | cut -d ' ' -f 1
cat /tmp/8ca319486bfbbc3663ea0fbe81326349
```

lv23→lv24

https://dev.to/christianpaez/bandit-level-23-level-24-10lo

The username is bandit24

The password is gb8KRRCsshuZXI0tUuR6ypOFjiZbf3G8

lv24→lv25

```
nano /tmp/test.sh
#!/bin/bash
password="gb8KRRCsshuZXI0tUuR6ypOFjiZbf3G8"
for i in $(seq -w 0000 9999)
do
 echo "$password $i" >>pins.txt
done
```

change the permissions I have

```
chmod +x /tmp/test.sh
```

run this code by typing

```
./test.sh
cat pins.txt | nc [localhost](<http://localhost>) 30002
```

The username is bandit25

The password is iCi86ttT4KSNe1armKiwbQNmB3YJP3q4

lv25→lv26

cat /etc/passwd



For the bandit26 which uses the showtext not the bash, check what is showtext



`more` is a shell command that allows the display of files in an interactive mode. Specifically, this interactive mode only works when the content of the file is too large to fully be displayed in the terminal window. One command that is allowed in the interactive mode is `v`. This command will open the file in the editor ‘vim’.

`ssh -i bandit26.sshkey [bandit26@localhost](<mailto:bandit26@localhost>) -p 2220` minimize the terminal window, press `v` to enter vim editor.

```
:e /etc/bandit_pass/bandit26
```

The username is bandit26

The password is s0773xxkk0MXfdqOfPRVr9L3jJBUOgCZ

lv26→lv27

```
./bandit27-do cat /etc/bandit_pass/bandit27
```

The username is bandit27

The password is upsNCc7vzaRDx6oZC6GiR6ERwe1MowGB

lv27→lv28

```
cd /tmp/
mkdir st
cd st
git clone ssh://bandit27-git@localhost:2220/home/bandit27-git/repo
cd repo
cat README
```

The username is bandit28

The password is Yz9IpL0sBcCeuG7m9uQFt8ZNpS4HZRcN

lv28→lv29

```
cd /tmp/
mkdir st
cd st
git clone ssh://bandit28-git@localhost:2220/home/bandit28-git/repo
cd repo
cat README
```

we find that, so we can check the log to see what is going on



```
git log
```



check the commit one by one

```
git show 73f5d0435070c8922da12177dc93f40b2285e22a
```

The username is bandit29

The password is 4pT1t5DENaYuqnqvadYs1oE4QLCdjmJ7

lv29→lv30

```
cd /tmp/
mkdir st
cd st
git clone ssh://bandit29-git@localhost:2220/home/bandit29-git/repo
cd repo
cat README
git log
```



we find nothing using `git show 5a53eb83a43bac1f0b4e223e469b40ef68a4b6e6` so it is in the branch.

```
git branch -a
```



`git show remotes/origin/dev`  and we find the password

The username is bandit30

The password is qp30ex3VLz5MDG1n91YowTv4Q8l7CDZL

lv30→lv31

The clone step is the same

```
git tag
git show secret
```

The username is bandit31

The password is fb5S2xb7bRyFmAvQYQGEqsbhVyJqhnDy

lv31→lv32

The steps of clone remains the same

```
cat README.md
```



```
vim key.txt
git add -f key.txt
git commit -m “a”
git push
```

The username is bandit32

The password is 3O9RfhqyAlVBEZpVb6LYStshZoqoSx5K

lv32→lv33

`$0`  this can help to escape the uppercase shell



The username is bandit33

The password is tQdtbs5D5i2vJwkO8mEyYEyTL8izoeJ0