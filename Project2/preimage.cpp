//Jared Staman

#include <iostream>
#include <string>
#include "hashlibpp.h"
#include <bitset>
#include <sstream>
#include <vector>
#include <bits/stdc++.h>

using namespace std;

double findMedian(vector<double> v);
string printRandomString(int n);
void find_average(string input, int bitsize, int num_tests); 
int find_same_hash(string input, int bitsize);
int compare_hashes(string a, string b);
vector<string> create_hash(string input, int bitsize);

int main(int argc, char** argv) {
	//error checks input	
	if (argc < 3) {
		cerr << "usage: ./preimage bitsize(8, 10, 12, 14, 16, 18, 20, 22)  number_of_tests\n";
		exit(0);
	}
	int bitsize, num_tests;
	bitsize = atoi(argv[1]);
	num_tests = atoi(argv[2]);

	srand(time(NULL));
	string seed = "a";
	find_average(seed, bitsize, num_tests);
	return 0;

}

//used to check variance from expected values
double findMedian(vector<double> v) {

	sort(v.begin(), v.end());

	if (v.size() % 2 != 0) {
		return v[v.size() / 2];
	}

	return (v[v.size() / 2] + v[(v.size()-1) / 2]) / 2;
}

//used to create new input for sha hash
string printRandomString(int n) {
	char alphabet[26] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r' , 's', 't' , 'u', 'v', 'w', 'x', 'y', 'z' };

	string res = "";
	for(int i = 0; i < n; i++) {
		res = res + alphabet[rand() % 26];
	}

	return res;
}

void find_average(string input, int bitsize, int num_tests) {

	vector<double> v, v2, v3;
	double max = 0;
	double min = 999999999;
	double count;
	double median;
	double lower_quart;
	double upper_quart;

	double average = 0;
	double total_count = 0;
	int i;

	//runs num_tests times
	for(i = 0; i < num_tests; i++) {
		//new string to test
		input = printRandomString(5);
		count = find_same_hash(input, bitsize);
		v.push_back(count);
		if(count > max) {
			max = count;
		}
		else if(count < min) {
			min = count;
		}
		total_count += count;

	}

	sort(v.begin(), v.end());
	for(i = 0; i < v.size()/2; i++) {
		v2.push_back(v.at(i));
	}

	for(i = v.size() - 1; i > v.size() / 2; i--) {
		v3.push_back(v.at(i));
	}

	//printing section
	median = findMedian(v);
	lower_quart = findMedian(v2);
	upper_quart = findMedian(v3);
	average = total_count / num_tests;
	cout << "Min: " << min << "\nMax: " << max << "\nMedian: " << median << "\nAverage: " << average << endl;
	cout << "Lower Quart: " << lower_quart << "\nUpper Quart: " << upper_quart << endl;

	return;
}

//main difference between collision
int find_same_hash(string input, int bitsize) {
	
	int count = 0;
	string comp;
	vector<string> s;

	string str, str2;

	//simply creates hash
	s = create_hash(input, bitsize);
	str = s.at(1);
	comp = s.at(0);

	//then creates another hash to compare, loops until finds match
	while(compare_hashes(str, str2) != 1) {
		s = create_hash(comp, bitsize);
		str2 = s.at(1);
		comp = s.at(0);
		count++;
	}
	
	return count;
}

//checks if hashes are same
int compare_hashes(string a, string b) {
	int result;
	if(a == b) {
		result = 1;
	}
	else
	{
		result = 0;
	}
	return result;
}

//makes hash, truncates it to bitsize desired
vector <string> create_hash(string input, int bitsize) {
	
	hashwrapper *myWrapper = new sha256wrapper();
	vector<string> result;
	string str;
	stringstream ss;

	ss.str("");
	ss.clear();

	ss << myWrapper->getHashFromString(input);
	ss >> str;
	result.push_back(str);
	
	ss.str("");
	ss.clear();

	string output;
	output = str.substr(0,6);
	
	if(bitsize == 8) {
		bitset<8> b1(output.c_str()[0]);
		bitset<8> b2(output.c_str()[1]);
		ss << b1 << b2;
		ss >> output;
	}

	else if(bitsize == 10) {
		bitset<8> b1(output.c_str()[0]);
		bitset<8> b2(output.c_str()[1]);
		bitset<8> b3(output.c_str()[2]);
	//	b3 = b3 >> 4;
		ss << b3;
		ss >> str;
		ss.str("");
		ss.clear();
		str = str.substr(4,7);
		ss << b1 << b2 << str;
		ss >> output;
	}

	else if(bitsize == 12) {
		bitset<8> b1(output.c_str()[0]);
		bitset<8> b2(output.c_str()[1]);
		bitset<8> b3(output.c_str()[2]);
		ss << b1 << b2 << b3;
		ss >> output;
	}

	else if(bitsize == 14) {
		bitset<8> b1(output.c_str()[0]);
		bitset<8> b2(output.c_str()[1]);
		bitset<8> b3(output.c_str()[2]);
		bitset<8> b4(output.c_str()[3]);
//		b4 = b4 >> 4;
		ss << b4;
		ss >> str;
		ss.str("");
		ss.clear();
		str = str.substr(4,7);
		ss << b1 << b2 << b3 << str;
		ss >> output;
	}

	else if(bitsize == 16) {
		bitset<8> b1(output.c_str()[0]);
		bitset<8> b2(output.c_str()[1]);
		bitset<8> b3(output.c_str()[2]);
		bitset<8> b4(output.c_str()[3]);
		ss << b1 << b2 << b3 << b4;
		ss >> output;
	}

	else if(bitsize == 18) {
		bitset<8> b1(output.c_str()[0]);
		bitset<8> b2(output.c_str()[1]);
		bitset<8> b3(output.c_str()[2]);
		bitset<8> b4(output.c_str()[3]);
		bitset<8> b5(output.c_str()[4]);

//		b5 = b5 >> 4;
		ss << b5;
		ss >> str;
		ss.str("");
		ss.clear();
		str = str.substr(4,7);
		ss << b1 << b2 << b3 << b4 << str;
		ss >> output;
	}

	else if(bitsize == 20) {
		bitset<8> b1(output.c_str()[0]);
		bitset<8> b2(output.c_str()[1]);
		bitset<8> b3(output.c_str()[2]);
		bitset<8> b4(output.c_str()[3]);
		bitset<8> b5(output.c_str()[4]);
		ss << b1 << b2 << b3 << b4 << b5;
		ss >> output;
	}

	else if(bitsize == 22) {
		bitset<8> b1(output.c_str()[0]);
		bitset<8> b2(output.c_str()[1]);
		bitset<8> b3(output.c_str()[2]);
		bitset<8> b4(output.c_str()[3]);
		bitset<8> b5(output.c_str()[4]);
		bitset<8> b6(output.c_str()[5]);
//		b6 = b6 >> 4;
		ss << b6;
		ss >> str;
		ss.str("");
		ss.clear();
		str = str.substr(4,7);
		ss << b1 << b2 << b3 << b4 << b5 << str;
		ss >> output;
	}
	result.push_back(output);
	return result;
}
