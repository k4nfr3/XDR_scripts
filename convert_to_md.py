#-*- coding: utf-8 -*-
import sys
import json
import os

markdown = ""
tab = "  "
list_tag = '* '
htag = '#'
depth = 1

def loadJSON(file):
    with open(file, 'r') as f:
        data = f.read()
    return json.loads(data)


def parseJSON(json_block, depth):
    if isinstance(json_block, dict):
        parseDict(json_block, depth)
    if isinstance(json_block, list):
        parseList(json_block, depth)


def parseDict(d, depth):
    for k in d:
        if isinstance(d[k], (dict, list)):
            addHeader(k, depth)
            parseJSON(d[k], depth + 1)
        else:
            addValue(k, d[k], depth)


def parseList(l, depth):
    for value in l:
        if not isinstance(value, (dict, list)):
            index = l.index(value)
            addValue(index, value, depth)
        else:
            parseDict(value, depth)

def buildHeaderChain(depth):
    chain = list_tag * (bool(depth)) + htag * (depth + 1) + \
        ' value ' + (htag * (depth + 1) + '\n')
    return chain

def buildValueChain(key, value, depth):
    chain = tab * (bool(depth - 1)) + list_tag + \
        str(key) + ": " + str(value) + "\n"
    return chain

def addHeader(value, depth):
    chain = buildHeaderChain(depth)
    global markdown
    markdown += chain.replace('value', value.title())

def addValue(key, value, depth):
    chain = buildValueChain(key, value, depth)
    global markdown
    markdown += chain


def writeOut(markdown, output_file):
    with open(output_file, 'w+') as f:
        f.write(markdown)



def convert_bioc_to_md(file_path):
    # Read the content of the .bioc file
    with open(file_path, 'r') as bioc_file:
        # Skip the first line
        bioc_file.readline()
        
        # Read the second line (JSON content)
        json_content = json.loads(bioc_file.readline().strip()[1:-1])
        parseJSON(json_content, depth)
        global markdown
        markdown = markdown.replace('#######', '######')        
        # Convert JSON to pretty markup language (Markdown)
        #md_header = "## " + file_path + "\n\n"
        #md_content = markdown.markdown(json.dumps(json.loads(json_content), indent=4))
        
        # Create the new file name with .md extension
        md_file_path = os.path.splitext(file_path)[0] + '.md'
        
        # Write the Markdown content to the new file
        with open(md_file_path, 'w') as md_file:
            #md_file.write(md_header)
            md_file.write(markdown)
            print("[+] " + file_path + " = done")

def process_bioc_files(folder_path='.'):
    # Get a list of all files in the current folder with the .bioc extension
    bioc_files = [f for f in os.listdir(folder_path) if f.endswith('.bioc')]

    # Loop through each .bioc file and convert to .md
    for bioc_file in bioc_files:
        bioc_file_path = os.path.join(folder_path, bioc_file)
        convert_bioc_to_md(bioc_file_path)

if __name__ == "__main__":
    # Provide the path to the folder containing .bioc files
    folder_path = '.'  # Change this to your desired folder path
    process_bioc_files(folder_path)