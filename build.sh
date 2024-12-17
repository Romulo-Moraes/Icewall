cd controller/build
printf "> Building the controller <\n"
cmake --build .
cd ../../
cd src
printf "\n> Building the kernel module <\n"
make
cd ..
mkdir -p out
mv controller/build/wallctl out
mv src/icewall.ko out