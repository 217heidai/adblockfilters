import os
import hashlib
import requests

class Downloader(object):
    def __init__(self, fileName, url):
        self.__fileName = fileName
        self.__fileName_download = self.__fileName + '.download'
        self.__url = url

    def __CalcFileSha256(self, filename):
        with open(filename, "rb") as f:
            sha256obj = hashlib.sha256()
            sha256obj.update(f.read())
            hash_value = sha256obj.hexdigest()
            return hash_value

    def Download(self):
        def isConfigFile(filename):
            filestats = os.stat(filename)
            #print(f'File Size in Bytes is {filestats.st_size}')
            if filestats.st_size < 1024 * 6:
                return False
            return True
        
        isNeedUpdate = False
        try:
            if os.path.exists(self.__fileName_download):
                os.remove(self.__fileName_download)
            
            r = requests.get(self.__url) 
            with open(self.__fileName_download,'wb') as f:
                f.write(r.content)
            
            if not isConfigFile(self.__fileName_download):
                return False

            if os.path.exists(self.__fileName):
                sha256Old = self.__CalcFileSha256(self.__fileName)
                sha256New = self.__CalcFileSha256(self.__fileName_download)
                if sha256New != sha256Old:
                    os.remove(self.__fileName)
                    os.rename(self.__fileName_download, self.__fileName)
                    isNeedUpdate = True
                os.remove(self.__fileName_download)
            else:
                os.rename(self.__fileName_download, self.__fileName)
                isNeedUpdate = True
        except Exception as e:
            print(f'%s download failed: %s' % (os.path.basename(self.__fileName), e))
        finally:
            return isNeedUpdate

if __name__ == '__main__':
    pwd = os.getcwd()
    file = pwd + '/rules/neodev_hosts.txt'
    url = 'https://raw.githubusercontent.com/neodevpro/neodevhost/master/host'
    downloader = Downloader(file, url)
    if downloader.Download():
        print('need update')
