#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cpr/cpr.h>
#include <regex>
#include <sqlite3.h>
#include "json/json.h"

using namespace std;
using namespace cpr;
using namespace Json;

string enrichment_url = "https://api.abuseipdb.com/api/v2/check?";
string api_key = "99cf1e1eb8a6e51b730c8a322f467fd37146bf9dba2ca94dc494a56dd22c097c51e6226364324e4b";
string header = "{\"Key\" :" + api_key+"}";

//void storeIOC(map<string,vector<string>>);


static int callback(void* data, int argc, char** argv, char** azColName)
{
    int i;
    fprintf(stderr, "%s: ", (const char*)data);
  
    for (i = 0; i < argc; i++) {
        printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
    }
  
    printf("\n");
    return 0;
}

static int savefile(void* data, int argc, char** argv, char** azColName)
{
	ofstream myfile;
	myfile.open ("intel.csv");
	myfile << "Value, TLP, Type, Sighting, ConfidenceScore, maliciousness.\n";
    int i;
    fprintf(stderr, "%s: ", (const char*)data);
  
    for (i = 0; i < argc; i++) {
         string val = argv[i] ? argv[i] : "NULL");
		 myfile << val << \n;
    }
	
	myfile.close();
	cout << endl;
    return 0;
}


void getIOC(string HTML_Content, regex temp, string ioc,map<string,vector<string>>&m)
{
	smatch match;
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
			Response r = Get(Url{enrichment_url+ type +"="+temp}, Header{header});
			string js = r.text;
			int confidence_score = js["data"]["abuseConfidenceScore"];
			if(confidence_score>65)
			{
				sql = ("INSERT INTO IOCs VALUES( '" + temp + "', 'GREEN', '" + type + "' , 1, " + confidence_score +", 'Malicious');");
			}
			else
			{
				sql = ("INSERT INTO IOCs VALUES( '" + temp + "', 'GREEN', '" + type + "' , 1, " + confidence_score +", 'Non-Malicious');");
			}
			
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

void quickAddIntel(string type, string value)
{
	string temp = value;
	Response r = Get(Url{enrichment_url+ type +"="+ value}, Header{header});
	string js = r.text;
	int confidence_score = js["data"]["abuseConfidenceScore"];
	if(confidence_score>65)
	{
		sql = ("INSERT INTO IOCs VALUES( '" + temp + "', 'GREEN', '" + type + "' , 1, " + confidence_score +", 'Malicious');");
	}
	else
	{
		sql = ("INSERT INTO IOCs VALUES( '" + temp + "', 'GREEN', '" + type + "' , 1, " + confidence_score +", 'Non-Malicious');");
	}
	
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
map<string,vector<string>> parseIOC(string HTML_Content){
	regex ipv4("(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)");
	regex ipv6("(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))");
	regex email("(\\w+)(\\.|_)?(\\w*)@(\\w+)(\\.(\\w+))+");
	regex domain("\\b([a-z0-9]+(-[a-z0-9]+)*\\.)+[a-z]{2,}\\b");
	regex url("((http|https)://)(www.)?[a-zA-Z0-9@:%.\\+~#?&//=]{2,256}\\.[a-z]{2,6}\\b([-a-zA-Z0-9@:%.\\+~#?&//=]*)");
	
	// map<Type of IOC, List of IOC>
	
	map<string,vector<string>> m ;
	getIOC(HTML_Content, ipv4,"ipv4",m);
	getIOC(HTML_Content, ipv6,"ipv6", m);
	getIOC(HTML_Content, email,"email", m);
    getIOC(HTML_Content, domain,"domain", m);
    getIOC(HTML_Content, url,"url", m);
	return m;
}

string MakeRequest(string url)
{
	Response r = Get(Url{url});
	cout << "Status code: " << r.status_code << '\n';
	string HTML_Content = r.text;
	return HTML_Content;	
}


void getData(string ioc_type)
{
	string query = "select value from IOCs where type = " + ioc_type;
	exit = sqlite3_exec(DB, query.c_str(), callback , 0, &messaggeError);
	if(exit != SQLITE_OK) 
	{
		cerr << "Error Gettting values" << endl;
		cerr<<messaggeError;
		sqlite3_free(messaggeError);	
	}
	else
	{
		cout << "Retrieved successfully" << endl;
	}
	
	
}

void exportExcel()
{
	// Not Implemented Yet
}
void exportCSV()
{
	string query = "select * from IOCs";
	
	exit = sqlite3_exec(DB, query.c_str(), savefile , 0, &messaggeError);
	if(exit != SQLITE_OK) 
	{
		cerr << "Error While executing query" << endl;
		cerr<<messaggeError;
		sqlite3_free(messaggeError);	
	}
	else
	{
		cout << "Query executed successfully" << endl;
	}
}

int main()
{
	cout << endl << endl << "     **---- Welcome to Threat Intel Provider ----**          " << endl << endl;
	
	cout << "Enter 1 to Fetch the IOCs from URL" << endl;
	cout << "Enter 2 to quick add the Intel" << endl;
	cout << "Enter 3 for getting IOC of specific type from Database" << endl;
	cout << "Enter 4 for exporting the Data in CSV or Excel format" << endl;
	
	int option;
	cin >> option;
	
	switch(option)
	{
		case 1:
		{
			string url;
			cout << "Enter the URL" << endl;
			cin >> url;
			string HTML_Content = MakeRequest(url);
			map<string,vector<string>>m = parseIOC(HTML_Content);		
			storeIOC(m);
			break;
		}
		case 2:
		{
			cout << "Enter the IOC type ";
			string ioc_type;
			cin >> ioc_type;
			
			cout << endl;
			cout << "Enter value of the IOC: ";
			string value;
			cin >> value;
			cout << endl;
			break;
		}
		case 3:
		{
			cout << "Enter the IOC type ";
			string ioc_type;
			cin >> ioc_type;
			
			getData(ioc_type);
			break;
		}
		case 4:
		{
			cout << "Enter the file format in which you want to import" << endl;
			cout << "Provide the input as csv or excel" << endl;
			
			string filetype;
			cin >> filetype;
			
			if(filetype == "csv")
			{
				exportCSV();
			}
			else
			{
				exportExcel();
			}
			break:
		}
		default:
		{
			cout << "INVALID INPUT" << endl;
		}
	}
}