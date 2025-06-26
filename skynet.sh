PATH=$PATH:.

rm -f skynet skynet_client skynet_decrypt skynet_encrypt skynet_keygen skynet.txt.sky skynet.txt.sky.dec

INC="$(pkg-config --cflags openssl)"
LIB="$(pkg-config --libs openssl)"

gcc $INC -o skynet skynet.c skynet_conv.c    skynet_proto.c $LIB
gcc $INC -o skynet_client   skynet_client.c  skynet_proto.c $LIB
gcc $INC -o skynet_decrypt  skynet_decrypt.c skynet_proto.c $LIB
gcc $INC -o skynet_encrypt  skynet_encrypt.c skynet_proto.c $LIB
gcc $INC -o skynet_keygen   skynet_keygen.c  skynet_proto.c $LIB

skynet_keygen npg_control      --server
skynet_keygen npg_pli          --server
skynet_keygen npg_surveillance --server
skynet_keygen npg_chat         --server
skynet_keygen npg_c2           --server
skynet_keygen npg_alerts       --server
skynet_keygen npg_logistics    --server
skynet_keygen npg_coord        --server
skynet_keygen server           --server
skynet_keygen client           --client

cp ~/.skynet/ecc/secp384r1/*.ec_pub ~/.skynet_client/ecc/secp384r1/

skynet_encrypt client server skynet.txt
skynet_decrypt client server skynet.txt.sky
