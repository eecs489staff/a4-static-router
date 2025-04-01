cd ~
git clone https://github.com/protocolbuffers/protobuf.git
cd protobuf
git checkout tags/v28.3
git submodule update --init --recursive
mkdir cmake/build
cd cmake/build
cmake -Dprotobuf_BUILD_TESTS=OFF ../..
make -j 8
sudo make install
cd ~/a4-static-router
./py_setup.sh