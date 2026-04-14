import requests
import time

infile = r"ready_list"
transit_file_inPy = r"transit_py.txt"
transit_file_inPA = r"transit_pa.txt"
outfile = r"domain.txt"
whitefile = r"whitelist.txt"

white_read = open(whitefile, "r")
tran_PA = open(transit_file_inPA, "w+")
fin = open(infile, "w+")

delete_list = ["","","","","",""," "]

for line in white_read:
    for word in delete_list:
        line = line.replace(word, "")
    tran_PA.write(line)

tran_PA.close()
tran_PA = open(transit_file_inPA, "r")

for line in tran_PA:
    if line.strip():
        fin.write(line)

tran_PA.close()
fin.close()

delete_list = ["*.","^.","^.^.","www.^.","www.*.","/*"]

fin = open(infile, "r")
tran_write = open(transit_file_inPy, "w+")
fout = open(outfile, "w+")

for line in fin:
    tran_write.write(line.split("/", 1)[0].rstrip() + '\n')

tran_write.close()
tran_read = open(transit_file_inPy, "r")

for line in tran_read:
    for word in delete_list:
        line = line.replace(word, "")
    fout.write(line)

fin.close()
tran_read.close()
fout.close()


def file_operation_execute(fname):
    domain = 'https://www.virustotal.com/vtapi/v2/domain/report'
    url = 'https://www.virustotal.com/vtapi/v2/url/report'
    content_array = []

    global arr_counter
    global params
    global var_a
    global var_b
    global var_c
    global var_d

    var_a = "'detected_urls': [{"
    var_b = "'detected_downloaded_samples': [{"
    var_c = "\"detected_communicating_samples': [{"
    var_d = "'positives': 0"

    arr_counter = 0

    global result_file
    result_file = ""

    with open(fname) as f:
        for line in f:
            content_array.append(line)

    array_maxlen = len(content_array)

    while (arr_counter != array_maxlen):
        content_array[arr_counter] = content_array[arr_counter].strip()

        params_domain = {
            'apikey': 'YOUR API IS HERE',
            'domain': content_array[arr_counter]
        }
        response = requests.get(domain, params=params_domain, verify=False)
        time.sleep(15)

        checking_memory_json = response.json()
        checking_memory = str(checking_memory_json)

        params_url = {
            'apikey': 'YOUR API IS HERE',
            'resource': content_array[arr_counter]
        }
        response = requests.get(url, params=params_url, verify=False)
        time.sleep(15)

        checking_memory_json = response.json()
        checking_memory += str(checking_memory_json)

        if var_a in checking_memory:
            result_file += (content_array[arr_counter] + " ")   # domen kotoriy nujno udalit
        elif var_b in checking_memory:
            result_file += (content_array[arr_counter] + " ")   # domen kotoriy nujno udalit
        elif var_c in checking_memory:
            result_file += (content_array[arr_counter] + " ")   # domen kotoriy nujno udalit
        elif var_d not in checking_memory:
            result_file += (content_array[arr_counter] + " ")   # domen kotoriy nujno udalit

        arr_counter += 1

    print(result_file)


file_operation_execute('domain.txt')
