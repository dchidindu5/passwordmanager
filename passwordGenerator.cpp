#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <windows.h>
#include <random>
#include <chrono>
#include <algorithm>
#include <iterator>
#include <time.h>

#define FILE_NAME "pwd.txt"

using namespace std;
static const std::vector<char> alphanum {'1','2','3','4','5','6','7','8','9', '!','@','#','$','%','^','&','*',
    'A','B','C','D','E','F','G','H','I','J','K','L','M','N','P','Q','R','S','T','U','V','W','X','Y','Z',
    'a','b','c','d','e','f','g','h','i','j','k','l','m','n','p','q','r','s','t','u','v','w','x','y','z'};
static  const std::vector<char> upperCase{alphanum.begin()+9, alphanum.begin()+34};

constexpr auto passwordSize = 15;


std::string password;
void erase(){
	std::ofstream out(FILE_NAME ,ios_base::out | ios_base::trunc);
	if(out.is_open()){
	out.clear();
	out.close();
	}
	else 
		cout<< "Unable to erase file " <<endl;
}

void save_vector(std::string &website, string& useracc, string& newpass){
	
	// writing date-time; & an extra '0' before every start of writing
    
    FILE *file = fopen(FILE_NAME, "a");
    time_t date = time(NULL);
    fprintf(file, "\n%s\t", ctime(&date));
    fclose(file);
	std::ofstream out(FILE_NAME, ios_base::out | ios_base::app);
    
	if (out.good()){
		
		out <<website << "\t" << useracc << "\t\t\t" << newpass;
		out << '\n';
		out.close();	
	}
		
else
	std::cout << "Unable to save the file\n";
	}


void gp(){
	cout<<" Password generated => ";
}


string generate_pwd(){
	
	auto seed = std::chrono::system_clock::now().time_since_epoch().count();//seed
    std::default_random_engine dre(seed);//engine
    std::uniform_int_distribution<int> d_all(0, alphanum.size()-1);//distribution for all characters
    std::uniform_int_distribution<int> d_upper(0, upperCase.size()-1);//distribution for uppercase only

    std::string password(passwordSize, ' ');//string to hold password
    auto it = upperCase.cbegin();
    std::advance(it, d_upper(dre));//advance iterator by random number b/w 0 and size of uppercase
    password[0] = *it;//choose the value of iterator after random advance as password[0]

    std::generate(password.begin()+1, password.end(), [&]{ return alphanum[d_all(dre)];});
    //http://en.cppreference.com/w/cpp/algorithm/generate
    //generate the rest of the characters for the password string

    cout << password << "\n";
    
    return password;
	
}

string insert_userpwd(std::string &website, string &useracc, string &newpass){
	
	//std::string website;
	std::cout << "Enter website name: ";
           std::cin >> website;

	//Username of account
            
	cout <<" Enter an account name: " << '\n';
	cin>> useracc;
	//getline(cin, useracc); 

	// Password entered by the user
	cout <<" Enter a password: " <<endl;
	//cin.getline(newpass);
	//getline(cin, newpass);
	cin>> newpass;
	
	return website;	
	return useracc;
		return newpass;

}

char opt(){
	char option;
	system("color 0F");
	
	cout <<" G)enerate password " << "S)ave " 
		<< "L)oad password " << "I)nsert Password "
		<< "E)rase " <<"Q)uit: ";
	cin >> option;
	return option;
}

int main(){
	
	//string clempty;
	std::string website;
	string acc, pass, genpass;
	bool done = false;
	
	
	
	while(!done){
		
	
		switch(opt()){
			
		case 'G':
		case 'g':
			
			std::cout << "Enter website name: ";
            
            std::cin >> website;
			
			cout<<" Enter account name: " ;
			cin>> acc;
			
		gp();	
		
		genpass = generate_pwd();
		
		
		
		//for(int i = 0; i< genpass[i]; i++){
			
			//cout<< genpass[i];
			
		//	Sleep(200);}
			
		
		 save_vector(website, acc, genpass);
		
			cout<<'\n';
		break;
		
		case 'S':
		case 's':
		save_vector(website, acc, pass);	
		break;
		
		case 'L':
		case 'l':
		break;
			
		case 'I':
		case 'i':
			insert_userpwd(website, acc, pass);
			break;
			
		case 'E':
		case 'e':
			erase();
			break;
			
	case 'Q':
	case 'q':
	done = true;
break;

		default: {
            std::cout << " Invalid choice. Try again. " << std::endl;
            break;}
		}
	}
}
