import pandas as pd 
import argparse
import os
import asyncio
import sys
import re
import ipaddress 
import datetime
import aiohttp
import time
import pycountry
import colorama

# to make the color works in CMD
colorama.init()

def Reading_IP(Filename):
    try:
        global start_time
        start_time = time.time()
        if Filename.endswith(".txt"):
            file_size = os.path.getsize(Filename)
            file_name = os.path.basename(Filename)

            if file_size == 0:
                print(f"\033[91m[!]\033[0m Error: The\033[91m {file_name} \033[0mis empty")
            else:
                print(f"\033[32m[*]\033[0m Collecting IP addresses from: \033[32m{file_name}\033[0m")
                
                All_Data = []
                with open(Filename, "r") as file:
                    for line in file:
                        values = line.split()
                        All_Data += values
                # Remove duplicate items
                All_IP = list(dict.fromkeys(All_Data))

                # Validate the list for only Public IP addresses
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                loop.run_until_complete(validate_ips(All_IP))
                loop.close()

        elif Filename.endswith('.csv'):
            Excel_csv = pd.read_csv(Filename,delimiter=',')
            file_name = os.path.basename(Filename)

            print(f"\033[32m[*]\033[0m Collecting IP addresses from: \033[32m{file_name}\033[0m ")

            # Combine the column names and values of a pandas DataFrame into a single list
            All_Data = Excel_csv.columns.tolist() + Excel_csv.values.ravel().tolist()

            # Remove NaN if found
            unfiltered_ip = [str(item) for item in All_Data if not pd.isnull(item)]

            # Remove any spaces found. It frequently happens that there is an unintentional space at the end of an IP address.
            All_IP = [item.strip() for item in unfiltered_ip]
            
            # Remove duplicate items
            All_IP = list(dict.fromkeys(All_IP))

            # Validate the list for only Public IP addresses
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(validate_ips(All_IP))
            loop.close()
        
        elif Filename.endswith('.xlsx'):
            Excel_xlsx = pd.read_excel(Filename)
            file_name = os.path.basename(Filename)

            # check if the excel fime is empty
            if len(Excel_xlsx.columns) == 0 and Excel_xlsx.empty:
                print(f"\033[91m[!]\033[0m Error: The\033[91m {file_name} \033[0mis empty")
                exit(1)
            else:
                print(f"\033[32m[*]\033[0m Collecting IP addresses from: \033[32m{file_name}\033[0m ")

                # Combine the column names and values of a pandas DataFrame into a single list
                All_Data = Excel_xlsx.columns.tolist() + Excel_xlsx.values.ravel().tolist()
            
                # to Remove NaN if found
                unfiltered_ip = [str(item) for item in All_Data if not pd.isnull(item)]
                
                # Remove any spaces found. It frequently happens that there is an unintentional space at the end of an IP address.
                All_IP = [item.strip() for item in unfiltered_ip]
            
                # Remove duplicate items
                All_IP = list(dict.fromkeys(All_IP))

                # Invoke validate_ips to validate the list for only Public IP addresses.
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                loop.run_until_complete(validate_ips(All_IP))
                loop.close()
        else: 
            print("\033[91m[!]\033[0m Error: Please choose a \033[91mtxt, csv or xlsx\033[0m" " file ")
            exit(1)
    except pd.errors.EmptyDataError:
        file_name = os.path.basename(Filename)
        print(f"\033[91m[!]\033[0m Error: The\033[91m {file_name} \033[0mis empty")
    except Exception as e:
        print("\033[91m[!]\033[0m Exception: {} ".format(e))
        exit(1)

def api_keys():
    try:
        # defining the dict of website names and empty API keys. 
        # incase of any errors the pre-defined dict will be parsed.
        apis = {'virustotal': 'empty', 'abuseipdb': 'empty'}

        with open(API_File, "r") as file:
            for line in file:
                words = [w.strip().lower() for w in line.split()]

                # I have in the text file comments lines starts with # and the below line is for skipping reading them.
                if words and words[0] == '#':
                    break

                # Check if the line contains at least two words (API name and key)
                # if the user entered only a name of the website without api key or vise versa the line will be skipped
                if len(words) < 2:
                    continue
                # validate if the user enters the correct website name
                api_name = words[0]
                if api_name not in apis:
                    raise ValueError(f'Unknown API name "{api_name}"')

                # Get the API key from the second word and all remaining words
                api_key = ' '.join(words[1:])
                apis[api_name] = api_key
        return apis
        
    except Exception as e:
        print("\033[91m[!]\033[0m Exception: {} ".format(e))
        print("\033[91m[!]\033[0m The API txt file is not in the correct format. The API keys must be written after the website name. For example, VirusTotal your_api_key.")
        # incase of error found during the text file the empty API keys will be returned and notify the user for an error in the format
        return apis
    
async def validate_ips(ips):
    try:
        # Regular expression pattern to match a valid IP address
        pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        
        public_ips = []
        
        private_ip = False
        
        for ip in ips:
            # Check if the IP address has square brackets and remove them if present --> incase of a sanitized IP address
            if '[' in ip:
                ip = ip.replace('[', '').replace(']', '')
            
            # Check if the IP address matches the pattern and is not a private IP address also, not been written before in the list.
            if re.match(pattern, ip) and not is_private(ip) and ip not in public_ips:
                public_ips.append(ip)
            # Check if the IP address notmatches the pattern and is  a private IP address  
            elif re.match(pattern, ip) and is_private(ip):
                # this flag is set to true to notify user whenever a private IP is provided. Line 166
                private_ip = True
    
        if len(public_ips) == 0:
            file_name = os.path.basename(Filename)
            print(f"\033[93m[!]\033[0m No public IP address was found in \033[93m{file_name}\033[0m")
            exit()
        elif private_ip and len(public_ips) >= 1:
            print("\033[93m[+]\033[0m Warning: Private IP addresses were found and have been excluded")

        api_key = api_keys()

        
        # Starting API requests phase
        if use_AbuseIPDB and use_VirusTotal:
            # if -av was provided
            VirusTotal_Response = await VirusTotal(public_ips, api_key)
            AbuseIPDB_Response = await AbuseIPDB(public_ips, api_key)
        elif use_AbuseIPDB:
            # if -a was provided
            VirusTotal_Response = None
            AbuseIPDB_Response = await AbuseIPDB(public_ips, api_key)
        elif use_VirusTotal:
            # if -v was provided
            VirusTotal_Response = await VirusTotal(public_ips, api_key)
            AbuseIPDB_Response = None
        else:
            # if neither was provided
            VirusTotal_Response = await VirusTotal(public_ips, api_key)
            AbuseIPDB_Response = await AbuseIPDB(public_ips, api_key)

        # Write the scan results to files
        Document_writing(VirusTotal_Response, AbuseIPDB_Response, public_ips)
    except Exception as e:
        print("\033[91m[!]\033[0m Exception: {} ".format(e))
    

def is_private(ip):
    private_ips = [
        "10.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16"
    ]
    
    for private_ip in private_ips:
        # Check if the input IP address is within the private IP address range
        if ipaddress.ip_address(ip) in ipaddress.ip_network(private_ip):
            return True
    return False    

# This is asyncronous method responsible for API fetching. primarily API requests and response will be processed in AbuseIPDB method
async def fetch_api(session, url, headers, params):
    # Asynchronous context manager to handle the session
    async with session.get(url=url, headers=headers, params=params) as resp:
        try:
            # Return the JSON response of the API call
            return await resp.json()
        except Exception as e:
            print("\033[91m[!]\033[0m Exception: {} ".format(e))

async def VirusTotal(Malicious_IPs, API_Key, error_faced = False):
    try:
        loading_task = None
        VirusTotal_URL = "https://www.virustotal.com/api/v3/ip_addresses/"
        API_Key = API_Key['virustotal']
        
        if API_Key == 'empty' or len(API_Key) < 40:
            print("\033[91m[!]\033[0m Error: Missing VirusTotal API key. If you don't want to use VirusTotal then specify -a to use AbuseIPDB only")
            return None
        
        headers = {"accept": "application/json",
                "x-apikey": API_Key}
        
        async with aiohttp.ClientSession() as session:

            gather_finished = False

            # Create tasks to fetch data for all malicious IPs
            tasks = [asyncio.ensure_future(fetch_api(session, VirusTotal_URL+i, headers, {'ipAddress': i, 'maxAgeInDays': '365'})) for i in Malicious_IPs]
            
            # Start the loading animation in a separate task
            loading_task = asyncio.create_task(animated_loading(lambda: gather_finished,'VirusTotal',error_faced))

            # Wait for all the tasks to complete and gather results
            responses = await asyncio.gather(*tasks)
            
            # Set the flag to indicate that the gather function has completed. 
            # the flag will stop the loading animation because its used as a parameter in line 241
            gather_finished = True
            
            Valid_IP_Counter = 0
            
            # Wait for the loading animation task to complete
            await loading_task
        
            VT_Success = [{'id': response['data'].get('id'), 'last_analysis_stats': response['data']['attributes'].get('last_analysis_stats'), 'country':response['data']['attributes'].get('country')} for response in responses if 'data' in response]
            
            printed_errors = set()

            for response in responses:
                json_Data = response
                if "error" in json_Data.keys():
                    errors = json_Data['error'].get("message")
                    if errors not in printed_errors:
                        print("\033[91m[!]\033[0m Error: {}".format(errors))
                        printed_errors.add(errors)
                # If data is present in the response, increase the Valid_IP_Counter
                elif 'data' in json_Data.keys():
                    # its used to count the successful processed IP addresses.
                    Valid_IP_Counter += 1

        if Valid_IP_Counter == 0:
            print("\033[91m[!]\033[0m No IP address has been processed by VirusTotal")
            return None
        else:
            return VT_Success
    except Exception as e:
        error_faced = True
        sys.stdout.write(f"\r\033[91m[!]\033[0m VirusTotal has not completed processing \n")
        sys.stdout.flush()
        if loading_task is not None:
            loading_task.cancel()
        print("\033[91m[!]\033[0m Exception: {} ".format(e))
                
async def AbuseIPDB(Malicious_IP, API_Key,error_faced=False):
    try:
        loading_task = None
        AbuseIPDB_URL = 'https://api.abuseipdb.com/api/v2/check'
        API_Key = API_Key['abuseipdb']

        
        if API_Key == 'empty' or len(API_Key) < 40:
            print("\033[91m[!]\033[0m Error: Missing AbuseIPDB API key. If you don't want to use AbuseIPDB then specify -v to use VirusTotal only")
            return None
        headers = { 'Accept': 'application/json','Key': API_Key}

        Valid_IP_Counter = 0
        
        # Main logic to perform multiple requests in parallel
        async with aiohttp.ClientSession() as session:

            gather_finished = False

            # Create tasks to fetch data for all malicious IPs
            tasks = [asyncio.ensure_future(fetch_api(session, AbuseIPDB_URL, headers, {'ipAddress': i, 'maxAgeInDays': '90'})) for i in Malicious_IP]
            
            # Start the loading animation in a separate task
            loading_task = asyncio.create_task(animated_loading(lambda: gather_finished,'AbuseIPDB',error_faced))
            
            # Wait for all the tasks to complete and gather results
            responses = await asyncio.gather(*tasks)
            
            # Set the flag to indicate that the gather function has completed. 
            # the flag will stop the loading animation because its used as a parameter in line 307
            gather_finished = True
        
            # Wait for the loading animation task to complete
            await loading_task

            sucessful_data = sorted([d['data'] for d in responses if 'data' in d], key=lambda x: x['abuseConfidenceScore'], reverse=True)
            
            printed_errors = set() 

            # Process each response
            for response in responses:
                json_Data = response
                
                if "errors" in json_Data.keys():
                    errors = json_Data.get('errors')
                    for error in errors:
                        error_detail = error.get('detail')
                        if error_detail not in printed_errors:
                            print("\033[91m[!]\033[0m Error: {}".format(error_detail))
                            printed_errors.add(error_detail)

                # If data is present in the response, increase the Valid_IP_Counter
                elif "data" in json_Data.keys():
                    Valid_IP_Counter += 1
                else:
                    print("\033[91m[!]\033[0m Error in request ... ")
                    errors = json_Data.get('errors')
                    for error in errors:
                        error_detail = error.get('detail')
                        if error_detail not in printed_errors:
                            print("\033[91m[!]\033[0m Error: {} ".format(error.get('detail')))
                            printed_errors.add(error_detail)

        if Valid_IP_Counter == 0:
            print("\033[91m[!]\033[0m No IP address has been processed by AbuseIPDB")
            return None
        else:
            return sucessful_data
    except Exception as e:
        error_faced = True
        sys.stdout.write(f"\r\033[91m[!]\033[0m AbuseIPDB has not completed processing \n")
        sys.stdout.flush()
        if loading_task is not None:
            loading_task.cancel()
        print("\033[91m[!]\033[0m Exception: {} ".format(e))

async def animated_loading(stop_animation,Website,error_faced=False):
    # Create the animation strings
    loading_animation = "|/-\\"
    dots_animation = ''
    i = 0
    # Keep running the loop until stop_animation is called
    while True:
        # Wait for 50ms before displaying the next character in the animation string
        await asyncio.sleep(0.05)
        # Display the current character in the animation string and overwrite the previous character
        sys.stdout.write(f"\r\033[96m[{loading_animation[i % len(loading_animation)]}]\033[0m {Website} processing{dots_animation}")

        # Flush the output to display it immediately
        sys.stdout.flush()
        i += 1
        # If stop_animation is called, exit the loop
        if stop_animation():
            # Flush the output to display it immediately once the API requests are finished
            sys.stdout.write(f"\r\033[32m[*]\033[0m {Website} has completed processing \n")
            sys.stdout.flush()
            break
        if error_faced:
            # Breaks whenever any exception is raised in VirusTotal or AbuseIPDB
            break
        # Add a dot to the end of the processing message every 10 iterations
        if i % 10 == 0:
            dots_animation += '.'
        # Print three dots and delete them after a delay of 200ms
        if len(dots_animation) == 4:
            sys.stdout.write('\b\b\b   ')
            sys.stdout.flush()
            dots_animation = ''

# converting country code to country name. to make it easier for analyst.
def get_country_name(code):
    try:
        return pycountry.countries.get(alpha_2=code).name
    except:
        return "Unknown"
    
def sorting_confidence(x):
    if x == 'N/A':
        return float('-inf')
    else:
        return float(x)

def Document_writing(VirusTotal,AbuseIPDB,IP_Address):
    try:
        if VirusTotal is None and AbuseIPDB is None:
            print("\033[91m[!]\033[0m No successful data were retrieved.")
            exit()

        df = pd.DataFrame(columns=['IP Address', 'Country', 'ISP', 'Usage Type', 'Domain', 'VirusTotal/Malicious', 
                            'VirusTotal/Clean', 'VirusTotal/Suspicious', 'AbuseIPDB/Confidence','AbuseIPDB/Total Reports'])

        # Check if AbuseIPDB is not None and loop over the results
        if AbuseIPDB is not None:
            for result in AbuseIPDB:
                # Create a new row with the necessary data
                row = {'IP Address': result['ipAddress'], 'Country': get_country_name(result['countryCode']),
                    'AbuseIPDB/Confidence': result['abuseConfidenceScore'], 'VirusTotal/Malicious': 'N/A',
                    'VirusTotal/Clean': 'N/A', 'VirusTotal/Suspicious': 'N/A', 'Usage Type': result['usageType'],
                    'ISP': result['isp'], 'Domain': result['domain'].replace('.','[.]'), 'AbuseIPDB/Total Reports': result['totalReports']}
                
                # Check if the IP address is already in the dataframe
                if result['ipAddress'] in df['IP Address'].values:
                    # If the IP address already exists, update the AbuseIPDB columns in the corresponding row
                    df.loc[df['IP Address'] == result['ipAddress'], 'AbuseIPDB/Confidence'] = result['abuseConfidenceScore']
                    df.loc[df['IP Address'] == result['ipAddress'], 'AbuseIPDB/Total Reports'] = result['totalReports']
                else:
                    # If the IP address does not exist, add the new row to the dataframe
                    df = pd.concat([df, pd.DataFrame([row], columns=df.columns)], ignore_index=True)

        # Check if VirusTotal is not None and loop over the results
        if VirusTotal is not None:
            for result in VirusTotal:
                # Check if the IP address is already in the dataframe
                if result['id'] in df['IP Address'].values:
                    # If the IP address already exists, update the VirusTotal columns in the corresponding row
                    df.loc[df['IP Address'] == result['id'], 'VirusTotal/Malicious'] = result['last_analysis_stats']['malicious']
                    df.loc[df['IP Address'] == result['id'], 'VirusTotal/Clean'] = result['last_analysis_stats']['harmless']
                    df.loc[df['IP Address'] == result['id'], 'VirusTotal/Suspicious'] = result['last_analysis_stats']['suspicious']
                    
                else:
                    # If the IP address does not exist, add a new row for the VirusTotal result
                    row = {'IP Address': result['id'], 'Country': get_country_name(result['country']),
                        'AbuseIPDB/Confidence': 'N/A', 'VirusTotal/Malicious': result['last_analysis_stats']['malicious'],
                        'VirusTotal/Clean': result['last_analysis_stats']['harmless'], 'VirusTotal/Suspicious': result['last_analysis_stats']['suspicious'],
                        'Usage Type': 'N/A', 'ISP': 'N/A', 'Domain': 'N/A', 'AbuseIPDB/Total Reports': 'N/A'}
                    df = pd.concat([df, pd.DataFrame([row], columns=df.columns)], ignore_index=True)
        if AbuseIPDB is None:
            df = df.sort_values(by='VirusTotal/Malicious', ascending=False, key=lambda x: x.apply(sorting_confidence), na_position='last')
        else:
            df = df.sort_values(by='AbuseIPDB/Confidence', ascending=False, key=lambda x: x.apply(sorting_confidence), na_position='last')

        Excel_name = f'VT AbuseIPDB Result {datetime.datetime.now().strftime("%Y-%m-%d %H-%M-%S")}.xlsx'
        Excel_file = os.path.join(Location, Excel_name)

        # Create a writer to save the DataFrame as an Excel file
        writer = pd.ExcelWriter(Excel_file, engine='xlsxwriter')

        # Write the DataFrame to a new worksheet named "VT-AbuseIPDB"
        df.to_excel(writer, sheet_name='VT-AbuseIPDB', index=False)

        # Create a workbook and add a worksheet
        workbook = writer.book
        worksheet = writer.sheets['VT-AbuseIPDB']

        # Add a format for the header row
        header_format = workbook.add_format({
            'bg_color': '#016174',  
            'font_color': 'white',  
            'bold': True,           
            'border': 1,           
            'align': 'center',      
            'valign': 'vcenter'     
        })

        # Write the column headers with the defined format
        for col_num, value in enumerate(df.columns.values):
            worksheet.write(0, col_num, value, header_format)
        
        # Close the ExcelWriter object to save the file and avoid the warning message
        writer.close()
        processed_addresses = df['IP Address'].tolist()
        
        missing_ip = False
        # printing how many successful IP addresses were processed
        if len(IP_Address) > len(processed_addresses):
            # if the processed IP addresses is less than the list of public IP addresses.
            print(f"\033[91m[!]\033[0m Total number of processed IP addresses: \033[91m{len(processed_addresses)} out of {len(IP_Address)} IP Addresses\033[0m ")
            missing_ip = True
        else:
            # if all IP addresses were successfully processed
            print(f"\033[96m[-]\033[0m Total Number of processed IP addresses: \033[96m{len(processed_addresses)} out of {len(IP_Address)} IP Addresses\033[0m ")

        # Print success message with the location of the csv file
        print("\033[32m[*]\033[0m CSV file has been created at this path: \033[32m{}".format(Location),"\033[0m ")
        
        if missing_ip:
            # Creating a text file with un processed IP addresses
            Text_name = f'Unprocessed IPs {datetime.datetime.now().strftime("%Y-%m-%d %H-%M-%S")}.txt'
            Text_file = os.path.join(Location, Text_name)

            # finding the unprocessed IP addressed
            Processed_ips = set(processed_addresses)
            Unprocessed_ips = set(IP_Address) - Processed_ips
            
            # Write unprocessed IP addresses to the txt file
            with open(Text_file, "w") as txtfile:
                for ip in Unprocessed_ips:
                    txtfile.write(ip + '\n')
            print("\033[91m[!]\033[0m TXT file has been created with unprocessed IP addresses at this location: \033[32m{} \033[0m ".format(Location))
        elapsed_time = time.time() - start_time
        print("\033[96m[-]\033[0m Elapsed time: " "\033[96m{:.2f} seconds\033[0m".format(elapsed_time))
    except Exception as e:
        # Print the error message in case of any exception
        print("\033[91m[!]\033[0m Exception: {} ".format(e)) 
        exit()

if __name__ == '__main__':
    ASCI_ART = """ 
████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
╚══██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
   ██║   ███████║██████╔╝█████╗  ███████║   ██║   ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
   ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║   ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
   ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║   ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝\n"""

    print(ASCI_ART)
    print("Author:\033[96m Muhannad Alruwais\033[0m")
    print('Email:\033[96m Muhannadbr1@gmail.com\033[0m')
    print('Twitter:\033[96m MuhannadRu\033[0m')
    print("Version:\033[96m 1.0 \033[0m \n")

    # Create the argument parser
    parser = argparse.ArgumentParser(
        prog="ThreatScanner.py", 
        description="Accepts: -f or --file for csv, xlsx or txt files only. Additionally, accepts a text file containing API keys.",
        usage="python3 ThreatScanner.py [-f] IP_File -api API_Key_File | optional -l -a -v  ",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="IP requirement:\n"
            "  The list of IP addresses can be provided as:\n"
            "    - A single IP address (e.g., 8.8.8.8)\n"
            "    - Multiple IP addresses separated by space (e.g., 8.8.8.8 8.8.4.4)\n"
            "    - Sanitized IP address (e.g., 8[.]8[.]8[.]8)"
    )

    # Add arguments to the parser
    parser.add_argument("-f", "--file", help="The path to the input file containing IP addresses. ", required=True)
    parser.add_argument("-l", "--location", help="Location to save the generated excel file. By default it will be created at the same directory", required=False)
    parser.add_argument("-a", "--AbuseIPDB", help="Use AbuseIPDB only to scan IP addresses. If neither -a nor -v is specified, both AbuseIPDB and VirusTotal will be used.", action='store_true')
    parser.add_argument("-v", "--VirusTotal", help="Use VirusTotal only to scan IP addresses. If neither -a nor -v is specified, both AbuseIPDB and VirusTotal will be used.", action='store_true')
    parser.add_argument("-api","--api", help="Path to API key text file.", required=True)

    # Check if any command-line arguments were provided
    if not len(sys.argv) > 1:
        # If no arguments were provided, print the help message and exit
        parser.print_help()
        exit()

    # assigning the inputs to variables
    args = parser.parse_args()
    Filename = args.file
    Location = args.location
    use_VirusTotal = args.VirusTotal
    use_AbuseIPDB = args.AbuseIPDB
    API_File = args.api

    # Validate if the IP file exist or not
    if not os.path.isfile(Filename):
        print("\033[91m[!]\033[0m Error: The IP file does not exist")
        exit(1)
    
    # Validate if the API file exist or not
    if not os.path.isfile(API_File):
        print("\033[91m[!]\033[0m Error: The API file does not exist")
        exit(1)

     #Validate the output location
    if not os.path.isdir(Location):
        print("\033[91m[!]\033[0m Error: The directory is not valid")
        exit(1)

    if Location is None or Location == '.':
        Location = os.getcwd()
    
    # Start reading the input file
    Reading_IP(Filename)