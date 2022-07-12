#!/bin/sh

zokrates compile -i powha_range.code 
cat signature_generator/input_data/first_try_walk_one | zokrates compute-witness
cat signature_generator/input_data/first_try_walk_two | zokrates compute-witness

zokrates compile -i powha_path_verification.code
cat signature_generator/input_data/first_try | zokrates compute-witness

zokrates setup

zokrates export-verifier

zokrates generate-proof

read -p "Want to clean up generated files? y/n: " cln
case $cln in
  [yY] ) rm geohash_points.json out out.code proof.json proving.key verification.key verifier.sol witness;
         echo "Done";
         exit;;
  [nN] ) echo "Exiting...";
         exit;;
esac