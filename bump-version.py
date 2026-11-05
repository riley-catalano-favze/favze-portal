import sys,re,glob,hashlib
js=sys.argv[1]
h=hashlib.sha1(open(js,'rb').read()).hexdigest()[:8]
n=0
for f in glob.glob('*.html'):
    s=open(f).read()
    t=re.sub(r'(src="%s)(\?v=[0-9a-f]+)?(")'%re.escape(js),r'\g<1>?v=%s\3'%h,s)
    if t!=s: open(f,'w').write(t); n+=1
print(js,h,n,'files')
