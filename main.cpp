#include <iostream>
#include <vector>
#include <string>
#include <cpr/cpr.h>
#include <regex>
#include <sqlite3.h>

using namespace std;
using namespace cpr;

//void storeIOC(map<string,vector<string>>);

void getIOC(string HTML_Content, regex temp, string ioc,map<string,vector<string>>&m)
{
	smatch match;
	//cout << "HTML_Content is: " << HTML_Content << endl;
    while (regex_search(HTML_Content, match, temp))
	{
		m[ioc].push_back(match.str(0));
        HTML_Content = match.suffix().str();
    }
	
	for(auto it=m.begin();it!=m.end();++it)
	{
		vector<string>v = (*it).second;
		for(int i=0;i<v.size();i++)
		{
			cout << v[i] << endl;
		}
	}
	return;
}

void storeIOC(map<string,vector<string>>&m)
{
	sqlite3* DB;
	int exit = 0;
	exit = sqlite3_open("example.db", &DB);
	
	
	if(exit) 
	{
		cerr << "Error open DB " << sqlite3_errmsg(DB) << endl;
		return;
	}
	else
	{
		cout << "Opened Database Successfully!" << endl;
	}
	
	string sql = "CREATE TABLE IOCs("
                      "VALUE CHAR(200) PRIMARY KEY NOT NULL, "
                      "TLP CHAR(20) NOT NULL, "
                      "TYPE CHAR(50) NOT NULL, "
                      "SIGHTING  INT  NOT NULL, "
                      "CONFIDENCE_SCORE  INT NOT NULL, "
                      "MALICIOUSNESS CHAR(50) NOT NULL);";
	char* messaggeError;
    exit = sqlite3_exec(DB, sql.c_str(), NULL, 0, &messaggeError);
	if(exit != SQLITE_OK) 
	{
        cerr << "Error Create Table" << endl;
		cerr<<messaggeError;
        //sqlite3_free(messaggeError);
    }
    else
	{
		cout << "Table created Successfully" << endl;
	}
	for(auto it=m.begin();it!=m.end();++it)
	{
		vector<string>v = (*it).second;
		string type = (*it).first;
		for(int i=0;i<v.size();i++)
		{
			string temp = v[i];
			sql = ("INSERT INTO IOCs VALUES( '" + temp + "', 'GREEN', '" + type + "' , 1, 60, 'Malicious');");
			exit = sqlite3_exec(DB, sql.c_str(), NULL, 0, &messaggeError);
			if(exit != SQLITE_OK) 
			{
				cerr << "Error Inserting values" << endl;
				cerr<<messaggeError;
				sqlite3_free(messaggeError);
			}
			else
			{
				cout << "Inserted Successfully" << endl;
			}
		}
	}
	
	sqlite3_close(DB);
}

void printIOC(string temp)
{
	cout << endl << endl << "Printing the data of: " << temp << endl;
	//for(auto x:m[temp])
	{
		//cout << x << endl;
	}
}

map<string,vector<string>> parsing(string HTML_Content){
	regex ipv4("(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)");
	regex ipv6("(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))");
	regex email("(\\w+)(\\.|_)?(\\w*)@(\\w+)(\\.(\\w+))+");
	regex domain("\\b([a-z0-9]+(-[a-z0-9]+)*\\.)+[a-z]{2,}\\b");
	regex url("((http|https)://)(www.)?[a-zA-Z0-9@:%.\\+~#?&//=]{2,256}\\.[a-z]{2,6}\\b([-a-zA-Z0-9@:%.\\+~#?&//=]*)");
	

	map<string,vector<string>> m ;
	getIOC(HTML_Content, ipv4,"ipv4",m);
	//printIOC("ipv4");
	return m;
	//getIOC(HTML_Content, ipv6,"ipv6");
	//printIOC("ipv6");
	//getIOC(HTML_Content, email);
    //getIOC(HTML_Content, domain);
    //getIOC(HTML_Content, url);
}

int main()
{
	cout << endl << endl << "     **---- Welcome to Threat Intel Provider ----**          " << endl << endl;
	cout << "Press 1: To Get Confidence score of URL" << endl;
	cout << "Press 2: To Get Confidence score of IPV4" << endl;
	cout << "Press 3: To Get Confidence score of IPV6" << endl;
	cout << "Press 4: To Get Confidence score of DOMAIN" << endl;
	cout << "Press 5: To Get Confidence score of EMAIL" << endl << endl;
	
	int choose_option;
	cin >> choose_option;
	
	switch(choose_option)
	{
		case 1:
		{
			string url;
			cout << "Enter the URL you want to fetch IOCs: ";
			cin >> url;
			Response r = Get(Url{url});
			cout << endl;
			//cout << "Status code: " << r.status_code << '\n';
			string HTML_Content = r.text;
			map<string,vector<string>>m = parsing(HTML_Content);
			storeIOC(m);
			break;
		}
		case 2:
		{
			break;
		}
		case 3:
		{
			break;
		}
		case 4:
		{
			break;
		}
		case 5:
		{
			break;
		}
		default:
		{
			cout << "INVALID INPUT" << endl;
			break;
		}
	}
	
}