## Logrip
Defend against AI crawlers & bots with server log analysis.

Copyright (c) Quanta Sciences, 2024-2025<br>
Rama Karl Hoetzlein, https://ramakarl.com<br>
<br>
Apache 2.0 License<br>
https://www.apache.org/licenses/LICENSE-2.0.txt

### Complete Demo
This is the complete example used in the video example as Blackhat 2025:
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
'''
