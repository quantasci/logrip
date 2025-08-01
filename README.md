## Logrip
Defend against AI crawlers & bots with server log analysis.

### Installation
Linux: Retrieve the two repos and use the build scripts provide.
```
git clone https://github.com/quantasci/libmin
git clone https://github.com/quantasci/logrip
cd libmin
./build.sh
cd ..
cd logrip
./build.sh
```
### Running Logrip
Running logrip requires two arguments as input:<br>
```
> logrip {access_log} {config_file.conf}
```
The access_log must be either .txt or .log<br>
The config_file must be .conf<br>
An example log and config file are provided.<br>

### Generating logs
Logrip takes a historic server access log as input.<br>
To generate these you would typically use journalctl, or others server tools that output logs.<br>
Here are examples of how to generate logs for apache2 or ruby-on-rails.<br>
How to generate Apache2 logs:<br>
```
> cd /var/log/apache2
> ls -l -a
> zcat access.log.*.gz > apache.log
> cat access.log.1 access.log >> apache.log
```
Now run logrip the apache.log input file along with the apache2.conf config file.<br>

How to generate Ruby-on-Rails logs:
```
> journalctl | grep {project} | grep 'Started GET' > ruby.log
```
Now run logrip with the ruby.log input file along with the ruby.conf config file.<br>

### Complete Demo
This is the complete example used in the video example at Blackhat 2025:
```
git clone https://github.com/quantasci/libmin
git clone https://github.com/quantasci/logrip
cd libmin
./build.sh
cd ..
cd logrip
./build.sh
cat assets/example_log.txt
cat assets/ruby.conf
../build/logrip/logrip example_log.txt ruby.conf
ls
xdg-open out_fig1.orig.png
xdg-open out_fig2_blocked.png
xdg-open out_fig3_filtered.png
cat out_ips.csv
```

### License
Copyright (c) Quanta Sciences, 2024-2025<br>
Rama Karl Hoetzlein, https://ramakarl.com<br>
<br>
Apache 2.0 License<br>
https://www.apache.org/licenses/LICENSE-2.0.txt
