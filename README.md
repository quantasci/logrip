<img src="https://github.com/quantasci/logrip/blob/main/assets/logrip_banner.png" />

## Logrip
Defend against AI crawlers & bots with server log analysis.<br>

Presented at Blackhat USA 2025, this is the official repository for:<br>
<a href="https://www.blackhat.com/us-25/briefings/schedule/#protecting-small-organizations-in-the-era-of-ai-bots-45666">Protecting Small Organizations in the Era of AI Bots, R. Hoetzlein, 2025</a><br>

Manual: <a href="https://github.com/quantasci/logrip/blob/main/docs/logrip_manual.pdf">Logrip Manual ver 1</a>

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
The executable logrip will be in ../build/logrip

### Running Logrip
Running logrip requires two arguments as input:<br>
```
> logrip {access_log} {config_file.conf}
```
The access_log must be either .txt or .log<br>
The config_file must be .conf<br>
An example log and config file are provided.<br>
After installation you can quickly test logrip by doing: ./run.sh<br>

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

### Config File & Policy Settings
A config file (.conf) controls the log parsing and the policy settings for blocking.
One would typically use, copy or modify an existing .conf file provided in /assets and then customize.<br>
The full list of config settingscan be found in the manual here:<br>
Manual: <a href="https://github.com/quantasci/logrip/blob/main/docs/logrip_manual.pdf">Logrip Manual ver 1.0</a>

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
