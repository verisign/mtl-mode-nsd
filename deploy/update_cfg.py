#!/usr/bin/python3
#
# 	Copyright (c) 2026, VeriSign, Inc.
# 	All rights reserved.
#
# 	Redistribution and use in source and binary forms, with or without
# 	modification, are permitted (subject to the limitations in the disclaimer
# 	below) provided that the following conditions are met:
#
# 		* Redistributions of source code must retain the above copyright notice,
# 		this list of conditions and the following disclaimer.
#
# 		* Redistributions in binary form must reproduce the above copyright
# 		notice, this list of conditions and the following disclaimer in the
# 		documentation and/or other materials provided with the distribution.
#
# 		* Neither the name of the copyright holder nor the names of its
# 		contributors may be used to endorse or promote products derived from this
# 		software without specific prior written permission.
#
# 	NO EXPRESS OR IMPLIED LICENSES TO ANY PARTY'S PATENT RIGHTS ARE GRANTED BY
# 	THIS LICENSE. THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
# 	CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# 	LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
# 	PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
# 	CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
# 	EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# 	PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
# 	BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
# 	IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# 	ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# 	POSSIBILITY OF SUCH DAMAGE.
#
import os

def clean_config(cfg_file):
    config_data = []

    with open(cfg_file,"r") as cfg:
        for l in cfg:
            if l.strip().lower() == 'zone:':
                break
            config_data.append(l)
    
    with open(cfg_file,"w") as cfg:
        for l in config_data:
            cfg.write(l)
        cfg.write("\n")
            

def add_zones(cfg_file, path):
    with open(cfg_file,"a") as cfg:
        for zfile in os.listdir(path):
            if zfile.lower().endswith(".signed"):
                znamestr = zfile.lower().replace('.zone.signed','')
                if(znamestr == "root"):
                    znamestr = "."
                cfg.write(f"zone:\n")
                cfg.write(f"\tname: \"{znamestr}\"\n")
                cfg.write(f"\tzonefile: \"{zfile}\"\n")


def main():
    clean_config("/usr/local/etc/nsd/nsd.conf")
    add_zones("/usr/local/etc/nsd/nsd.conf", "/var/nsd/data/zones")


if __name__ == "__main__":
    main()