/**
	@file
	@brief a sample of BLS signature
	see https://github.com/herumi/bls
	@author MITSUNARI Shigeo(@herumi)
	@license modified new BSD license
	http://opensource.org/licenses/BSD-3-Clause

*/
#include <mcl/bn256.hpp>
#include <iostream>
#include <sstream>
#include <vector>
#include <chrono>
#include <math.h>
#include <errno.h>

#include "mcl/SHA256.h"

using namespace mcl::bn256;

void Hash_pk(G1& P, const G2& pk)
{
	// G2 (Point) --> G1 (Point)
	Fp t;
	t.setHashOf(pk.getStr(0));
	mapToG1(P, t);
}

std::string Hash_1(const std::string& m)
{
	// {0,1}^* (String) --> {0,1}^{\ell} (String)
	int ell = 240;
	int sub = floor((256 - ell) / 4.0);
	SHA256 sha;
	sha.update(m);
	uint8_t * hashvalue = sha.digest();
	return SHA256::toString(hashvalue).substr(sub);	// return ell bits strings
}

void Hash_2(G1& P, const std::string& m)
{
	// {0,1}^*(String) --> G1 (Point)
	Fp t;
	t.setHashOf(m);
	mapToG1(P, t);
}

void KeyGen(Fr& sk, G2& pk, G1& pi, const G2& Q)
{
	G1 Hpk;
	sk.setRand();
	G2::mul(pk, Q, sk); // pk = sQ
	Hash_pk(Hpk, pk);
	G1::mul(pi, Hpk, sk); // pi = s H(pk)
}

std::string compute_h(std::string& m, const std::vector<G2>& pk_list, const std::vector<Fr>& r_list){
	std::string tmp;
	tmp = m;
	for(auto& itr: pk_list){
		tmp += itr.getStr();
	}
	for(auto& itr: r_list){
		tmp += itr.getStr();
	}
	return Hash_1(tmp);
}

void Sign(G1& sigma, std::string& h, const Fr& sk, const std::string& m)
{
	G1 Hm;
	Hash_2(Hm, m + h);
	G1::mul(sigma, Hm, sk); // sigma = s H(m,h)
}

void AggSig(G1& sigma_agg, const std::vector<G1>& sigma_list)
{
	sigma_agg.clear();
	for(auto& itr: sigma_list){
		G1::add(sigma_agg, sigma_agg, itr); // sigma_agg = sigma_1 + ... + sigma_N
	}
}

void AggKey(G2& pk_agg, const std::vector<G2>& pk_list, const std::vector<G1>& pi_list, const G2& Q){
	// Check proof of possession
	int i;
	int N = pk_list.size();
	for(i = 0; i < N; i++){
		G2 pk = pk_list[i];
		G1 pi = pi_list[i];
		G1 Hpk;
		Fp12 e1, e2;
		Hash_pk(Hpk, pk);
		pairing(e1, pi, Q); // e1 = e(sigma, Q)
		pairing(e2, Hpk, pk); // e2 = e(Hm, sQ)
		if(e1 != e2){
			printf("Error: Proof of possession check is faild.");
			std::exit(0);
		}
	}
	// Compute pk_agg
	pk_agg.clear();
	for(auto& pk: pk_list){
		G2::add(pk_agg, pk_agg, pk); // pk_agg = pk_1 + ... + pk_N
	}
}

bool Verify(const G1& sigma, const std::string& h, const G2& Q, const G2& pk, const std::string& m)
{
	Fp12 e1, e2;
	G1 Hm;
	Hash_2(Hm, m + h);
	pairing(e1, sigma, Q); // e1 = e(sigma, Q)
	pairing(e2, Hm, pk); // e2 = e(Hm, sQ)
	// for debug
	// std::cout << "e1. " << e1 << std::endl;
	// std::cout << "e2. " << e2 << std::endl;

	return e1 == e2;
}

int main()
{
	// input
	std::string m;
	int N;
	std::cout << "Type your message." << std::endl;
	std::cin >> m;
	std::cout << "Type the number of signers." << std::endl;
	std::cin >> N;

	// setup parameter
	initPairing();
	G2 Q;
	mapToG2(Q, 1);
	std::string h;

	// key list
	int i;
	std::vector<Fr> sk_list;
	std::vector<G2> pk_list;
	std::vector<G1> pi_list;
	std::vector<G1> sigma_list;
	
	// KeyGen
	auto start = std::chrono::system_clock::now();
	for(i = 0; i < N; i++ ){
		Fr sk;
		G2 pk;
		G1 pi;
		KeyGen(sk, pk, pi, Q);
		sk_list.push_back(sk);
		pk_list.push_back(pk);
		pi_list.push_back(pi);
		// for debug
		// std::cout << "Signer. " << i << std::endl;
		// std::cout << "secret key: " << sk << std::endl;
		// std::cout << "public key: " << pk << std::endl;
		// std::cout << "PoPs: " << pi << std::endl;
	}
	auto end = std::chrono::system_clock::now();
	auto dur = end - start;
	auto msec = std::chrono::duration_cast<std::chrono::milliseconds>(dur).count();
	std::cout << "KeyGen Time: " << msec << " [ms]" << std::endl;
	
	// Signing
	start = std::chrono::system_clock::now();
	//Round 1
	std::vector<Fr> r_list;
	for(i = 0; i < N; i++ ){
		Fr r;
		r.setRand();
		r_list.push_back(r);
	}

	//Round 2
	h = compute_h(m, pk_list, r_list); // h = H(m || pk1 || ... || pk_N || r_1 || ... || r_N)

	//Round 3
	for(i = 0; i < N; i++ ){
		// Sign
		G1 sigma;
		Fr sk = sk_list[i];
		Sign(sigma, h, sk, m);
		sigma_list.push_back(sigma);
		// for debug
		// std::cout << "msg: " << m << std::endl;
		// std::cout << "signature: " << sigma << ", " << h << std::endl;
		
		// // Individual signatures verify
		// G2 pk = pk_list[i];
		// bool ok = Verify(sigma, h, Q, pk, m);
		// std::cout << "verification result :" << (ok ? "Success" : "Failed") << std::endl;
	}
	end = std::chrono::system_clock::now();
	dur = end - start;
	msec = std::chrono::duration_cast<std::chrono::milliseconds>(dur).count();
	std::cout << "Signing Time: " << msec << " [ms]" << std::endl;
	
	// Aggregate Signature
	G1 sigma_agg;
	start = std::chrono::system_clock::now();
	AggSig(sigma_agg, sigma_list);
	end = std::chrono::system_clock::now();
	dur = end - start;
	msec = std::chrono::duration_cast<std::chrono::milliseconds>(dur).count();
	std::cout << "Signature Aggregation Time: " << msec << " [ms]" << std::endl;
	
	// for debug
	//std::cout << "aggregated signature: " << sigma_agg << std::endl;

	// Aggregated Publickey
	G2 pk_agg;
	start = std::chrono::system_clock::now();
	AggKey(pk_agg, pk_list, pi_list, Q);
	end = std::chrono::system_clock::now();
	dur = end - start;
	msec = std::chrono::duration_cast<std::chrono::milliseconds>(dur).count();
	std::cout << "Key Aggregation Time: " << msec << " [ms]" << std::endl;
	
	// for debug
	// std::cout << "aggregated public key: " << pk_agg << std::endl;

	// for debug: check publickey
	// Fr sk_agg;
	// sk_agg = 0;
	// for(auto& itr:sk_list){
	// 	sk_agg += itr;
	// }
	// G2 pk_agg_d;
	// G2::mul(pk_agg_d, Q, sk_agg);
	// std::cout << "Aggregated public key2: " << pk_agg_d << std::endl;

	// Verify
	start = std::chrono::system_clock::now();
	bool ok = Verify(sigma_agg, h, Q, pk_agg, m);
	end = std::chrono::system_clock::now();
	dur = end - start;
	msec = std::chrono::duration_cast<std::chrono::milliseconds>(dur).count();
	std::cout << "Verification Time: " << msec << " [ms]" << std::endl;
	std::cout << "verification result :" << (ok ? "Success" : "Failed") << std::endl;
}