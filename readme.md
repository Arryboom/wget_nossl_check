# A Simple Trick to patch wget to avoid ssl certificate check
Well,recently I got a Gargoyle router which is x86_64 arch,simple flash sys img into this router,and found that I can't use opkg update because of opkg sign error and wget ssl certificate check error like below:  

```
root@llll:/etc# opkg update
Downloading http://downloads.openwrt.org/chaos_calmer/15.05/x86_64/generic/packages/base/Packages.gz.
Downloading http://downloads.openwrt.org/chaos_calmer/15.05/x86_64/generic/packages/base/Packages.sig.
Signature check failed.
Remove wrong Signature file.

```
1.So first we need to disable signature check of opkg,simple comment this line in /etc/opkg.conf  

```
root@aaaa:/etc# cat opkg.conf 
dest root /
dest ram /tmp
lists_dir ext /var/opkg-lists
option overlay_root /overlay
#option check_signature 1
```
![](/3.png)  
2.Then I got error like

```
root@OpenWrt:~# opkg update
Downloading https://downloads.openwrt.org/ba ... /base//Packages.gz.
Downloading https://downloads.openwrt.org/ba ... /luci//Packages.gz.
Downloading https://downloads.openwrt.org/ba ... kages//Packages.gz.
Downloading https://downloads.openwrt.org/ba ... kages//Packages.gz.
Downloading https://downloads.openwrt.org/ba ... uting//Packages.gz.
Collected errors:
* opkg_download: Failed to download https://downloads.openwrt.org/ba ... s/base//Packages.gz, wget returned 5.
* opkg_download: Failed to download https://downloads.openwrt.org/ba ... s/luci//Packages.gz, wget returned 5.
* opkg_download: Failed to download https://downloads.openwrt.org/ba ... ckages//Packages.gz, wget returned 5.
* opkg_download: Failed to download https://downloads.openwrt.org/ba ... ckages//Packages.gz, wget returned 5.
* opkg_download: Failed to download https://downloads.openwrt.org/ba ... outing//Packages.gz, wget returned 5.
* To connect to archive.openwrt.org insecurely, use `--no-check-certificate‘.
```

3.First make sure you got right DNS configuration in /etc/resolve.conf  
Then I found that "To connect to archive.openwrt.org insecurely",means there is another certificate check failed.  
I tried rename wget,wget-ssl to owget,owget-ssl in /usr/bin,and then create a sh script with content "owget --no-check-certificate $@",then ln xx.sh wget and wget-ssl,but doesn't work yet,opkg update show wget return 1,still failed,so I have to try another way.  

4.use wget --version I got this is wget-1.17.1.Quickly I got source code of this version from https://ftp.gnu.org/gnu/wget/  

But if you think I gonna modify the source code and recompile it,no,I'm too lazy to config cross compile enviroment since this is not a very well known linux distrbution and I may hang on configuration of cross compile enviroment for a long time.Simple use IDA to patch it :)  

5.First I searched "--no-check-certificate" string and found the function we need should be in wget-1.17.1\src\openssl.c  

--- 
```
ssl_check_certificate (int fd, const char *host)
{
  X509 *cert;
  GENERAL_NAMES *subjectAltNames;
  char common_name[256];
  long vresult;
  bool success = true;
  bool alt_name_checked = false;

  /* If the user has specified --no-check-cert, we still want to warn
     him about problems with the server's certificate.  */
  const char *severity = opt.check_cert ? _("ERROR") : _("WARNING");

  struct openssl_transport_context *ctx = fd_transport_context (fd);
  SSL *conn = ctx->conn;
  assert (conn != NULL);

  /* The user explicitly said to not check for the certificate.  */
  if (opt.check_cert == CHECK_CERT_QUIET)
    return success;

  cert = SSL_get_peer_certificate (conn);
  if (!cert)
    {
      logprintf (LOG_NOTQUIET, _("%s: No certificate presented by %s.\n"),
                 severity, quotearg_style (escape_quoting_style, host));
      success = false;
      goto no_cert;             /* must bail out since CERT is NULL */
    }

  IF_DEBUG
    {
      char *subject = _get_rfc2253_formatted (X509_get_subject_name (cert));
      char *issuer = _get_rfc2253_formatted (X509_get_issuer_name (cert));
      DEBUGP (("certificate:\n  subject: %s\n  issuer:  %s\n",
               quotearg_n_style (0, escape_quoting_style, subject),
               quotearg_n_style (1, escape_quoting_style, issuer)));
      xfree (subject);
      xfree (issuer);
    }

  vresult = SSL_get_verify_result (conn);
  if (vresult != X509_V_OK)
    {
      char *issuer = _get_rfc2253_formatted (X509_get_issuer_name (cert));
      logprintf (LOG_NOTQUIET,
                 _("%s: cannot verify %s's certificate, issued by %s:\n"),
                 severity, quotearg_n_style (0, escape_quoting_style, host),
                 quote_n (1, issuer));
      xfree(issuer);

      /* Try to print more user-friendly (and translated) messages for
         the frequent verification errors.  */
      switch (vresult)
        {
        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
          logprintf (LOG_NOTQUIET,
                     _("  Unable to locally verify the issuer's authority.\n"));
          break;
        case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
        case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
          logprintf (LOG_NOTQUIET,
                     _("  Self-signed certificate encountered.\n"));
          break;
        case X509_V_ERR_CERT_NOT_YET_VALID:
          logprintf (LOG_NOTQUIET, _("  Issued certificate not yet valid.\n"));
          break;
        case X509_V_ERR_CERT_HAS_EXPIRED:
          logprintf (LOG_NOTQUIET, _("  Issued certificate has expired.\n"));
          break;
        default:
          /* For the less frequent error strings, simply provide the
             OpenSSL error message.  */
          logprintf (LOG_NOTQUIET, "  %s\n",
                     X509_verify_cert_error_string (vresult));
        }
      success = false;
      /* Fall through, so that the user is warned about *all* issues
         with the cert (important with --no-check-certificate.)  */
    }

  /* Check that HOST matches the common name in the certificate.
     #### The following remains to be done:

     - When matching against common names, it should loop over all
       common names and choose the most specific one, i.e. the last
       one, not the first one, which the current code picks.

     - Ensure that ASN1 strings from the certificate are encoded as
       UTF-8 which can be meaningfully compared to HOST.  */

  subjectAltNames = X509_get_ext_d2i (cert, NID_subject_alt_name, NULL, NULL);

  if (subjectAltNames)
    {
      /* Test subject alternative names */

      /* Do we want to check for dNSNAmes or ipAddresses (see RFC 2818)?
       * Signal it by host_in_octet_string. */
      ASN1_OCTET_STRING *host_in_octet_string = a2i_IPADDRESS (host);

      int numaltnames = sk_GENERAL_NAME_num (subjectAltNames);
      int i;
      for (i=0; i < numaltnames; i++)
        {
          const GENERAL_NAME *name =
            sk_GENERAL_NAME_value (subjectAltNames, i);
          if (name)
            {
              if (host_in_octet_string)
                {
                  if (name->type == GEN_IPADD)
                    {
                      /* Check for ipAddress */
                      /* TODO: Should we convert between IPv4-mapped IPv6
                       * addresses and IPv4 addresses? */
                      alt_name_checked = true;
                      if (!ASN1_STRING_cmp (host_in_octet_string,
                            name->d.iPAddress))
                        break;
                    }
                }
              else if (name->type == GEN_DNS)
                {
                  /* dNSName should be IA5String (i.e. ASCII), however who
                   * does trust CA? Convert it into UTF-8 for sure. */
                  unsigned char *name_in_utf8 = NULL;

                  /* Check for dNSName */
                  alt_name_checked = true;

                  if (0 <= ASN1_STRING_to_UTF8 (&name_in_utf8, name->d.dNSName))
                    {
                      /* Compare and check for NULL attack in ASN1_STRING */
                      if (pattern_match ((char *)name_in_utf8, host) &&
                            (strlen ((char *)name_in_utf8) ==
                                (size_t) ASN1_STRING_length (name->d.dNSName)))
                        {
                          OPENSSL_free (name_in_utf8);
                          break;
                        }
                      OPENSSL_free (name_in_utf8);
                    }
                }
            }
        }
      sk_GENERAL_NAME_pop_free(subjectAltNames, GENERAL_NAME_free);
      if (host_in_octet_string)
        ASN1_OCTET_STRING_free(host_in_octet_string);

      if (alt_name_checked == true && i >= numaltnames)
        {
          logprintf (LOG_NOTQUIET,
              _("%s: no certificate subject alternative name matches\n"
                "\trequested host name %s.\n"),
                     severity, quote_n (1, host));
          success = false;
        }
    }

  if (alt_name_checked == false)
    {
      /* Test commomName */
      X509_NAME *xname = X509_get_subject_name(cert);
      common_name[0] = '\0';
      X509_NAME_get_text_by_NID (xname, NID_commonName, common_name,
                                 sizeof (common_name));

      if (!pattern_match (common_name, host))
        {
          logprintf (LOG_NOTQUIET, _("\
    %s: certificate common name %s doesn't match requested host name %s.\n"),
                     severity, quote_n (0, common_name), quote_n (1, host));
          success = false;
        }
      else
        {
          /* We now determine the length of the ASN1 string. If it
           * differs from common_name's length, then there is a \0
           * before the string terminates.  This can be an instance of a
           * null-prefix attack.
           *
           * https://www.blackhat.com/html/bh-usa-09/bh-usa-09-archives.html#Marlinspike
           * */

          int i = -1, j;
          X509_NAME_ENTRY *xentry;
          ASN1_STRING *sdata;

          if (xname) {
            for (;;)
              {
                j = X509_NAME_get_index_by_NID (xname, NID_commonName, i);
                if (j == -1) break;
                i = j;
              }
          }

          xentry = X509_NAME_get_entry(xname,i);
          sdata = X509_NAME_ENTRY_get_data(xentry);
          if (strlen (common_name) != (size_t) ASN1_STRING_length (sdata))
            {
              logprintf (LOG_NOTQUIET, _("\
    %s: certificate common name is invalid (contains a NUL character).\n\
    This may be an indication that the host is not who it claims to be\n\
    (that is, it is not the real %s).\n"),
                         severity, quote (host));
              success = false;
            }
        }
    }


  if (success)
    DEBUGP (("X509 certificate successfully verified and matches host %s\n",
             quotearg_style (escape_quoting_style, host)));
  X509_free (cert);

 no_cert:
  if (opt.check_cert == CHECK_CERT_ON && !success)
    logprintf (LOG_NOTQUIET, _("\
To connect to %s insecurely, use `--no-check-certificate'.\n"),
               quotearg_style (escape_quoting_style, host));

  return opt.check_cert == CHECK_CERT_ON ? success : true;
}
```
--- 







6.Actually you don't need check source code here,but here I want make sure no mistake.  
Then We can get wget-ssl(in Gargoyle wget was only a link to wget-ssl) and put it into IDA.  
![](/2.png)  
from searching "--no-check-certificate" in string window of IDA we can know it's in 000000000045A67C,and double click it from string window will bring us to Main view and we know that sub_4295F9 has a read it.  

![](/5.png)
![](/6.png)
Here we use "F5" to decompile it  
![](/7.png)
![](/8.png)  
We can see it's almost 100% similar to source code,this the function ssl_check_certificate() we want to change,and we want to change this function to make it always return true.So check the Assemble and use IDA's plugin KeyPatch to modify it without using other tool.
In source code we can know modify 
```
  if (opt.check_cert == CHECK_CERT_QUIET)
    return success;
```
to 
```
if (true)
	return success;
```
would be a easy way.so here we do the same,found that 0000000000429632 would be the assemble of this,and because of cdecl call defination and some compiler's optimization,the return function was loca_429A7F,and here we know last line 0000000000429632 was "if",so here we change 
```
0000000000429632 jnz     short loc_42963B  
```
to "nop" or "jmp loc_429634" should be work.  

--- 
![](/9.png)
![](/10.png) 

then save it and upload it to your router,should able to normally start your "opkg update" and other installation tasks.


![](/1.png)  



Guess only few people using X86_64 version of Gargoyle,but here I'm still upload the patched wget for somebody who got into similar trouble,remember to backup your orignal file before using it to replace oringal one.  

File: Z:\wget_nossl_check\wget-ssl  
Size: 430817 bytes  
MD5: C317F18F583151B3D05778C9417E12DE  
SHA1: C18AF1FE244B13496D06810C1EF9A3CA82C92FBF  
CRC32: 5201D170  


