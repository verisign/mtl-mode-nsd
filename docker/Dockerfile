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

# Use the pqc_base image that has the depenencies available
FROM pqc_mtl_mode:latest as nsd-mtl-build

USER root
RUN dnf -y install autoconf automake gcc make libevent-devel flex bison libtool

# Set the working directory in the container
RUN mkdir -p /usr/local/app 
WORKDIR /usr/local/app

#######################################
# Build the LDNS Library with the PQC extensions
#######################################
COPY ./src /usr/local/app

RUN touch zparser.y && autoconf -V
RUN cd simdzone && autoreconf -fi && cd ..
RUN libtoolize -ci && aclocal && autoconf && autoheader 
RUN ./configure --enable-root-server --enable-draft-mtl
RUN make && make nsd-mem

# Setup the runnable image
FROM pqc_mtl_mode:latest 

# Setup the nsd use
RUN groupadd nsd; adduser nsd -g nsd
RUN dnf install -y libevent net-tools tcpdump python3.14

RUN mkdir -p /usr/local/sbin /usr/local/etc/nsd
COPY --from=nsd-mtl-build /usr/local/app/nsd /usr/local/sbin
COPY --from=nsd-mtl-build /usr/local/app/nsd-checkconf /usr/local/sbin
COPY --from=nsd-mtl-build /usr/local/app/nsd-checkzone /usr/local/sbin
COPY --from=nsd-mtl-build /usr/local/app/nsd-control /usr/local/sbin
COPY --from=nsd-mtl-build /usr/local/app/nsd-mem /usr/local/sbin
COPY --from=nsd-mtl-build /usr/local/app/nsd-control-setup.sh /usr/local/sbin/nsd-control-setup

COPY deploy/nsd.conf /usr/local/etc/nsd
RUN mkdir -p /var/nsd/data/zones

COPY deploy/update_cfg.py deploy/docker-entrypoint.sh /var/nsd
RUN chown -R nsd:nsd /var/nsd
RUN mkdir -p /var/db/nsd && chown  nsd:nsd /var/db/nsd
RUN chmod 744 /var/nsd/docker-entrypoint.sh

ENTRYPOINT ["/var/nsd/docker-entrypoint.sh"]