__author__ = 'ned'

import os
import sys
import yara
import time
import magic
import struct
import pefile
import ssdeep
import hashlib
import sqlite3
import optparse
import binascii
import subprocess
import ConfigParser



def ConfigSectionMap(section):
    dict1 = {}
    options = Config.options(section)
    for option in options:
        try:
            dict1[option] = Config.get(section, option)
            if dict1[option] == -1:
                DebugPrint("skip: %s" % option)
        except:
            print("exception on %s!" % option)
            dict1[option] = None
    return dict1

Config = ConfigParser.ConfigParser()
Config.read("config.ini")

RULES = ConfigSectionMap("folders")['yararules']

def enumerateDir(path):
	files = []
	for f in os.listdir(path):
		if os.path.isdir(path+f) is True:
			pass
		else:
			files.append(path+f)
	return files

def parseSample(sample):
	dicts = []
	sampleDict = {}
	sampleDict['File'] = sample
	sampleDict['MD5'] = getMD5(open(sample).read())
	sampleDict['SHA256'] = getSHA256(open(sample).read())
	sampleDict['SSDeep'] = getSSDeep(sample)
	sampleDict['File Size'] = getSize(sample)
	sampleDict['File Magic'] = getMagic(sample)
	sampleDict['File Type'] = getFileType(sample)
	sampleDict['Compile Time'] = getCompileTime(open(sample).read())
	sampleDict['Entry Point'] = getEntryPoint(sample)
	sampleDict['Import Hash'] = getImpHash(open(sample).read())
	sampleDict['PEHash'] = getPEhash(sample)
	sampleDict['RichSig'] = getRichSig(sample)
	sampleDict['Sections'] = getSectionInfo(sample)
	sampleDict['Resources'] = getPEResource(open(sample).read())
	sampleDict['Imports'] = checkImport(sample)
	sampleDict['Exports'] = checkExports(sample)
	sampleDict['Yara'] = yaraScan(sample)
	sampleDict['Version'] = dumpVersion(sample)
	sampleDict['Cert'] = checkCert(sample)
	dicts.append(sampleDict)
	return dicts

def getMagic(f):
	return magic.from_file(f)

def getFileType(f):
	mime = magic.Magic(mime=True)
	return mime.from_file(f)

def getRichSig(f):
	# code borrowed from crits
    # Generate a signature of the block. Need to apply checksum
    # appropriately. The hash here is sha256 because others are using
    # that here.
    #
    # Most of this code was taken from pefile but modified to work
    # on the start and checksum blocks.

    pe = pefile.PE(f)
    rich_hdr = pe.parse_rich_header()
    if not rich_hdr:
        return
    data = {"raw": str(rich_hdr['values'])}

    try:
        rich_data = pe.get_data(0x80, 0x80)
        if len(rich_data) != 0x80:
            return None
        data = list(struct.unpack("<32I", rich_data))
    except pefile.PEFormatError as e:
        return None

    checksum = data[1]
    headervalues = []

    for i in xrange(len(data) // 2):
        if data[2 * i] == 0x68636952: # Rich
            if data[2 * i + 1] != checksum:
                print 'Rich Header corrupted'
            break
        headervalues += [data[2 * i] ^ checksum, data[2 * i + 1] ^ checksum]

    sha_256 = hashlib.sha256()
    for hv in headervalues:
        sha_256.update(struct.pack('<I', hv))
    return sha_256.hexdigest()

def getPEResource(f):
	try:
		pe = pefile.PE(data=f)
		resourcesList = []
		if hasattr(pe,"DIRECTORY_ENTRY_RESOURCE"):
			for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
				type = pefile.RESOURCE_TYPE.get(entry.id, 'NA')
				for e in entry.directory.entries:
					for m in e.directory.entries:
						lang = pefile.LANG.get(m.data.lang, '*unknown*')
						sublang = pefile.get_sublang_name_for_lang(m.data.lang, m.data.sublang)
						rva = m.data.struct.OffsetToData
						size = m.data.struct.Size
						data = pe.get_data(rva,size)
						name = entry.name
						resources = (type,hashlib.sha256(data).hexdigest(),hashlib.md5(data).hexdigest(),lang,sublang,size)
						resourcesList.append(resources)
			return resourcesList
	except:
		return

def getSectionInfo(f):
	pe = pefile.PE(f)
	sectionList = []
	for s in pe.sections:
		sections = (s.Name,s.get_hash_md5(),s.get_hash_sha256(),s.VirtualAddress,hex(s.Misc_VirtualSize),s.SizeOfRawData,s.get_entropy())
		sectionList.append(sections)
	return sectionList

def getImpHash(f):
	try:
		pe = pefile.PE(data=f)
		return pe.get_imphash()
	except:
		return

def checkImport(f):
	hits = []
	pe = pefile.PE(f)
	try:
		for entry in pe.DIRECTORY_ENTRY_IMPORT:
			for imp in entry.imports:
				if imp.name != None:
					hits.append(imp.name)
		return hits
	except:
		return

def checkExports(f):
	hits = []
	pe = pefile.PE(f)
	try:
		for entry in pe.DIRECTORY_ENTRY_EXPORT.symbols:
			if (entry.name != None) and (entry.name != ""):
				hits.append(entry.name)
		return hits
	except:
		return

def checkCert(f):
	pe = pefile.PE(f)
	try:
		for entry in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
			if entry.name == 'IMAGE_DIRECTORY_ENTRY_SECURITY':
				if entry.Size == 0 and entry.VirtualAddress == 0:
					return
				signature = pe.write()[entry.VirtualAddress+8:]
				certDict = {}
				certDict['SHA256'] = hashlib.sha256(signature).hexdigest()
		return certDict
	except:
		return

def getMD5(f):
	return hashlib.md5(f).hexdigest()

def getSHA256(f):
	return hashlib.sha256(f).hexdigest()

def getSSDeep(f):
	return ssdeep.hash_from_file(f)

def getSize(f):
	return os.stat(f).st_size

def getEntryPoint(f):
	pe = pefile.PE(f)
	return pe.OPTIONAL_HEADER.AddressOfEntryPoint

def getCompileTime(f):
	try:
		pe = pefile.PE(data=f)
		return time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(pe.FILE_HEADER.TimeDateStamp))
	except:
		return

def dumpVersion(f):
	try:
		pe = pefile.PE(f)
		return pe.FileInfo[0].StringTable[0].entries.items()
	except:
		return

def getPEhash(f):
        try:
            pehash = subprocess.Popen('python ~/Dropbox/python/intel\ tools/pehash.py ' + f, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            if "can't open" in pehash:
                return False
            else:
                return pehash.stdout.read().rstrip('\n')
        except:
            return False

def yaraScan(f):
        try:
            rules = yara.compile(RULES)
            return rules.match(f)
        except:
            return False
    
def compareArrays(a,b):
  
    matchesCount=0
    for i,field in enumerate(a):
        
        if field:
            if field==b[i]:
                a[i]=""
                matchesCount+=1
        else:
            matchesCount+=1
                
    if matchesCount == len(a):
        print "Exact match of existing file in database, record won't be saved in table fileDB"
        return False
    
    return a
            

def outputData(d):
	print '=' * 130
	print 'METADATA'
	print '-' * 130
	print '%-15s %s' %('File', d['File'])
	print '%-15s %s' %('MD5', d['MD5'])
	print '%-15s %s' %('SHA256', d['SHA256'])
	print '%-15s %s' %('SSDeep', d['SSDeep'])
 	print '%-15s %s bytes' %('Size ', d['File Size'])
 	print '%-15s %s' %('File Magic', d['File Magic'])
 	print '%-15s %s' %('File Type', d['File Type'])
 	print '%-15s %s' %('Compile Time', d['Compile Time'])
 	print '%-15s %s' %('Entry Point', hex(d['Entry Point']))
 	print '%-15s %s' %('Import Hash', d['Import Hash'])
 	print '%-15s %s' %('PEHash', d['PEHash'])
 	print '%-15s %s' %('Rich Header', d['RichSig'])

 	try:
 		if d.get('Cert',{}):
 			print '\nCERTIFICATE INFO'
 			print '=' * 130
 			print '%-50s %s' %('Certificate File','SHA256')
 			print '-' * 130
 			c = d.get('Cert',{})
 			print '%-50s %s' %(c.get('File'),c.get('SHA256'))
 	except:
 		pass

	try:
		if d.get('Sections',[]):
			print '\nSECTION INFO'
			print '=' * 180
			print '%-15s %-35s %-65s %-15s %-15s %-15s %-15s' %('Name','MD5','SHA256','VirtAddr','VirtSize','RawSize','Entropy')
			print '-' * 180
			for s in d.get('Sections',[]):
				print '%-18s %-35s %-65s %-15s %-15s %-15s %-15s' %(s[0],s[1],s[2],s[3],s[4],s[5],s[6])
	except:
		pass

	try:
		if d.get('Resources',[]):
			print '\nRESOURCES'
			print '=' * 180
			print '%-15s %-65s %-35s %-15s %-26s %s' %('TYPE','SHA256','MD5','LANG','SUBLANG','SIZE')
			print '-' * 180
		for r in d.get('Resources',[]):
			print '%-15s %-65s %-35s %-15s %-25s %s' %(r[0],r[1],r[2],r[3],r[4],r[5])
	except:
		pass

	if d['Version']:
		print '\nVERSION INFO'
		print '-' * 130
		for k,v in d['Version']:
			print '%s: %s' %(k,v)

	if d.get('Yara',[]):
		print '\nYARA'
		print '-' * 130
		for y in d.get('Yara',[]):
			print '{:<15}'.format(y)

	try:
		if d.get('Imports',[]):
			print '\nSUSPICIOUS IMPORTS'
			print '-' * 130
			for i in d.get('Imports',[]):
				print '{:<30}'.format(i)
	except:
		pass

	try:
		if d.get('Exports',[]):
			print '\nEXPORTS'
			print '-' * 130
			for e in d.get('Exports',[]):
				print '{:<30}'.format(e)
	except:
		pass

	print '\n'

def save_to_db(samp):
    file_md5 = samp.get('MD5','')
    file_sha256 = samp.get('SHA256','')
    file_ssdeep = samp.get('SSDeep','')
    file_magic = samp.get('File Magic','')
    file_type = samp.get('File Type','')
    file_compile_time = samp.get('Compile Time','')
    file_import_hash = samp.get('Import Hash','')
    try:
        file_pehash = samp.get('PEHash','')
    except:
        file_pehash = ''
    try:
        file_rich_hash = samp.get('RichSig','')
    except:
        file_rich_hash = ''
    try:
        file_certificate_hash = samp.get('Cert',{}).get('SHA256','')
    except:
        file_certificate_hash = ''
    try:
        yara_hits = samp.get('Yara',[])
    except:
        yara_hits = []
    try:
        section_hashes = samp.get('Sections',[])
    except:
        section_hashes = []
    try:
        resource_hashes = samp.get('Resources',[])
    except:
        resource_hashes = []

    fileValues = [None,file_md5,file_sha256,file_ssdeep,file_magic,file_type,file_compile_time,file_import_hash,file_pehash,file_rich_hash,file_certificate_hash,None]
    
    DBfolder=ConfigSectionMap("folders")['dbfolder']
    
    if os.path.isdir(DBfolder) is False:
        os.mkdir(DBfolder)
    if os.path.isfile(DBfolder+"yasbat.db") is False:
        conn = sqlite3.connect(DBfolder+"yasbat.db")
        conn.execute('''CREATE TABLE fileDB (
                        id INTEGER PRIMARY KEY,
                        file_md5 VARCHAR(32),
                        file_sha256 VARCHAR(64),
                        file_ssdeep VARCHAR(255),
                        file_magic VARCHAR(255),
                        file_type VARCHAR(255),
                        file_compile_time VARCHAR(255),
                        file_import_hash VARCHAR(32),
                        file_pehash VARCHAR(64),
                        file_rich_hash VARCHAR(64),
                        file_certificate_hash VARCHAR(64),
                        is_duplicate_of INT(1) DEFAULT NULL )''')
        conn.execute('''CREATE TABLE yaraDB (
                        file_md5 VARCHAR(32) NOT NULL,
                        yara_hit VARCHAR(255) NOT NULL,
                        FOREIGN KEY(file_md5) REFERENCES fileDB(file_md5))''')
        conn.execute('''CREATE TABLE sectionDB (
                        file_md5 VARCHAR(32) NOT NULL,
                        section_name VARCHAR(255) NOT NULL,
                        section_md5 VARCHAR(32) NOT NULL,
                        section_sha256 VARCHAR(64) NOT NULL,
                        FOREIGN KEY(file_md5) REFERENCES fileDB(file_md5))''')
        conn.execute('''CREATE TABLE resourceDB (
                        file_md5 VARCHAR(32) NOT NULL,
                        resource_type VARCHAR(255) NOT NULL,
                        resource_lang VARCHAR(255) NOT NULL,
                        resource_sublang VARCHAR(255) NOT NULL,
                        resource_md5 VARCHAR(32) NOT NULL,
                        resource_sha256 VARCHAR(64) NOT NULL,
                        FOREIGN KEY(file_md5) REFERENCES fileDB(file_md5))''')
    else:
        conn = sqlite3.connect(DBfolder+'yasbat.db')

    #check for duplicates based on md5hash
    duplicateID=False
    sql="SELECT * FROM fileDB WHERE file_md5='"+fileValues[1]+"'"
    try:
        duplicate=conn.execute(sql).fetchone()
    except:
        #It's not a duplicate
        pass
    
    insert=True
    
    if duplicate:
        
        compareCheck=compareArrays(fileValues,duplicate)
        if compareCheck:
          
            if fileValues:
                
                fileValues[11]=duplicate.id
                insert=False
        else:
            insert=False
    
    if insert:
    
        try:
            fileStmt = "INSERT INTO fileDB VALUES (?,?,?,?,?,?,?,?,?,?,?,?)"
            conn.execute(fileStmt,(fileValues))
        except sqlite3.IntegrityError:
            return

    try:
        yaraStmt = "INSERT INTO yaraDB VALUES (?,?)"
        for hit in yara_hits:
            conn.execute(yaraStmt,(file_md5,str(hit)))
    except Exception, e:
        print 'Something went wrong (yara) ... %s | %s' %(e,file_md5)

    try:
        sectStmt = "INSERT INTO sectionDB VALUES (?,?,?,?)"
        for sect in section_hashes:
            conn.execute(sectStmt,(file_md5,sect[0],sect[1],sect[2]))
    except Exception, e:
        print 'Something went wrong (sections) ... %s | %s' %(e,file_md5)

    try:
        rsrcStmt = "INSERT INTO resourceDB VALUES (?,?,?,?,?,?)"
        for rsrc in resource_hashes:
                conn.execute(rsrcStmt,(file_md5,rsrc[0],rsrc[3],rsrc[4],rsrc[2],rsrc[1]))
    except Exception, e:
        print 'Something went wrong (resources) ... %s | %s' %(e,file_md5)

    conn.commit()
    conn.close()
    return

def isPE(f):
	fopen = open(f,'rb')
	if binascii.hexlify(bytearray(fopen.read()))[0:4] == '4d5a':
		return True
	else:
		print 'Not a valid PE file'

def readConfig(args):
	usage = "Usage: python %prog [options]"
	parser = optparse.OptionParser(usage=usage)
	parser.add_option('--directory', '-d', action='store', default=None, help='Directory to enumerate')
	parser.add_option('--file','-f', action='store', default=None, help='Analyze a file')
	parser.add_option('--save_to_db','-s', action='store_true', default=None, help='Save to DB')

	global options
	(options,file) = parser.parse_args(args)


def main(args):
    readConfig(args)
    if options.file:
        if isPE(options.file):
            samp = parseSample(options.file)[0]
            outputData(samp)
            if options.save_to_db:
                save_to_db(samp)
    if options.directory:
        for f in enumerateDir(options.directory):
            if isPE(f):
                for x in parseSample(f):
                    outputData(x)
                    if options.save_to_db:
                        save_to_db(x)

if __name__ == '__main__':
    args = sys.argv[1:]
    if args:
        main(args)
    else:
        print "See help (-h) for details"
        sys.exit(0)