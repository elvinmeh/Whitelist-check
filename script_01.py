import requests

infile = r"ready_list"
outfile = r"cleaned_file.txt"

delete_list = ["*.","^.","^.^.","www.^.","www.*.","/*","www."]

fin = open(infile, "r")
fout = open(outfile, "w+")

for line in fin:
    for word in delete_list:
        line = line.replace(word, "")
    fout.write(line)

fin.close()
fout.close()


def file_operation_execute(fname):
    url = 'https://www.virustotal.com/vtapi/v2/domain/report'
    content_array = []

    global arr_counter
    global params
    global var_a
    global var_b
    global var_c

    var_a = "'detected_urls': [{"
    var_b = "'detected_downloaded_samples': [{"
    var_c = "\"detected_communicating_samples': [{"

    arr_counter = 0

    global result_file
    result_file = ""

    with open(fname) as f:
        for line in f:
            content_array.append(line)

    array_maxlen = len(content_array)

    while (arr_counter != array_maxlen):
        content_array[arr_counter] = content_array[arr_counter].strip()

        params = {
            'apikey': 'YOUR KEY IS HERE',
            'domain': content_array[arr_counter]
        }

        response = requests.get(url, params=params)
        checking_memory_json = response.json()
        checking_memory = str(checking_memory_json)

        print(type(checking_memory))

        if var_a in checking_memory:
            result_file += (content_array[arr_counter] + " ")   # domen kotoriy nujno udalit
        elif var_b in checking_memory:
            result_file += (content_array[arr_counter] + " ")   # domen kotoriy nujno udalit
        elif var_c in checking_memory:
            result_file += (content_array[arr_counter] + " ")   # domen kotoriy nujno udalit

        arr_counter += 1

    print(result_file)


file_operation_execute('cleaned_file.txt')
