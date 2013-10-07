/*
  ------------------------------------------------------------
  INVITE Message Generator


  Luis Martin Gil <martingil.luis at gmail.com>
  ------------------------------------------------------------
 */
#include <pjsip.h>
#include <pjsip_ua.h>
#include <pjsip_simple.h>
#include <pjlib-util.h>
#include <pjlib.h>
#include <strings.h>
#include "util.h"
 
#define THIS_FILE      "img.c"
#define SIP_PORT        8000
#define AF	        pj_AF_INET()
#define POOL_SIZE       1024
#define MAX_FILE_SIZE   5000
#define CALL_ID_RSIZE   16

// SDP structures.
static pj_str_t mime_application = { "application", 11};
static pj_str_t mime_sdp = {"sdp", 3};
static pj_str_t dummy_sdp_str = {
  "v=0\r\n"
  "o=- 3360842071 3360842071 IN IP4 192.168.0.68\r\n"
  "s=pjmedia\r\n"
  "c=IN IP4 192.168.0.68\r\n"
  "t=0 0\r\n"
  "m=audio 4000 RTP/AVP 0 8 3 103 102 101\r\n"
  "a=rtcp:4001 IN IP4 192.168.0.68\r\n"
  "a=rtpmap:103 speex/16000\r\n"
  "a=rtpmap:102 speex/8000\r\n"
  "a=rtpmap:3 GSM/8000\r\n"
  "a=rtpmap:0 PCMU/8000\r\n"
  "a=rtpmap:8 PCMA/8000\r\n"
  "a=sendrecv\r\n"
  "a=rtpmap:101 telephone-event/8000\r\n"
  "a=fmtp:101 0-15\r\n",
  0
};

// Basic structure.
struct app
{
  pjsip_endpoint      *g_endpt;
  pj_caching_pool      cp;
  pj_pool_t*           pool;
  pjsip_dialog        *dlg;
  pjsip_tx_data       *tdata;
  pjsip_inv_session   *g_inv;
  pj_bool_t            g_complete;
  pjmedia_sdp_session *dummy_sdp;

  // Command line options are stored here.
  struct options
  {
    pj_bool_t       b_tcp; // Transport.
    pj_bool_t       b_udp;
    pj_bool_t       b_transport;

    pj_str_t	    uri; // Uri string.
    pj_bool_t       b_uri;

    pj_list         uriparams_list; // Optional URI params
    pj_bool_t       b_uriparams_list;

    pj_str_t	    boundary; // Boundary string.
    pj_bool_t       b_boundary;

    pjsip_hdr       hdr_list; // Optional headers will be stored at tdata_h->msg
    pj_bool_t       b_hdr_list;
    
    pjsip_msg_body  *body; // Body structure.
    pj_bool_t       b_single_body;
    pj_bool_t       b_multipart_body;

  } opt;
} app;

// Prototypes
static int get_headerName(pj_str_t  *source, pj_str_t *result);
static int get_headerValue(pj_str_t  *source, pj_str_t *result);
static int get_word(pj_str_t *source, pj_str_t *result, char delimeter);
// Callback to be called when invite session's state has changed.
static void call_on_state_changed( pjsip_inv_session *inv, pjsip_event *e);
// Callback to be called when dialog has forked
static void call_on_forked(pjsip_inv_session *inv, pjsip_event *e);
// Callback to be called to handle incoming requests outside dialogs.
static pj_bool_t on_rx_request( pjsip_rx_data *rdata );
// Basic use information function.
static void usage(void);
// Verify that valid SIP url is given.
static pj_status_t verify_sip_url(const char *c_url);
// Parsing the dummy/fake SCP.
static pj_status_t verify_scp();
// Key functions.
static pj_status_t init_options(); //Initialization.
static pj_status_t parse_options(int argc, char *argv[]); //Parsing command line.
static pj_status_t run(); //Sending the INVITE.

static pjsip_module mod_simpleua =
  {
    NULL, NULL,    /* prev, next.*/
    { "img", 3 },    /* Name.*/
    -1,    /* Id*/
    PJSIP_MOD_PRIORITY_APPLICATION, /* Priority*/
    NULL,    /* load()*/
    NULL,    /* start()*/
    NULL,    /* stop()*/
    NULL,    /* unload()*/
    &on_rx_request,    /* on_rx_request()*/
    NULL,    /* on_rx_response()*/
    NULL,    /* on_tx_request.*/
    NULL,    /* on_tx_response()*/
    NULL,    /* on_tsx_state()*/
  };

// ***************************************
// main INVITE Message Generator function.
// ***************************************
int main(int argc, char *argv[])
{
  pj_status_t status;

  printf("SIP INVITE generator using PJSIPv%s\n"
	 "Author: Luis Martin Gil\n(c)2011 martingil.luis@gmail.com\n\n",
	 PJ_VERSION);

  status = init_options();
  if (status != PJ_SUCCESS) {
    return -1;
  }

  status = parse_options(argc, argv);
  if (status != PJ_SUCCESS) {
    return -1;
  }

  status = run();
  if (status != PJ_SUCCESS) {
    return -1;
  }
  
  return 0;
}
// **************************************
// Verify that valid SIP url is given.
static pj_status_t verify_sip_url(const char *c_url)
{
  pjsip_uri *p;
  pj_pool_t *pool;
  char *url;
  int len = (c_url ? pj_ansi_strlen(c_url) : 0);

  if (!len) return -1;

  pool = pj_pool_create(&app.cp.factory, "check%p", 1024, 0, NULL);
  if (!pool) return PJ_ENOMEM;

  url = pj_pool_alloc(pool, len+1);
  pj_ansi_strcpy(url, c_url);
  url[len] = '\0';

  p = pjsip_parse_uri(pool, url, len, 0);
  if (!p || pj_stricmp2(pjsip_uri_get_scheme(p), "sip") != 0)
    p = NULL;

  pj_pool_release(pool);
  return p ? 0 : -1;
}

// Parsing the fake SCP.
static pj_status_t verify_scp() {
  pj_status_t status;
  {
    dummy_sdp_str.slen = pj_ansi_strlen(dummy_sdp_str.ptr);
    status = pjmedia_sdp_parse(app.pool, dummy_sdp_str.ptr, dummy_sdp_str.slen,
			       &app.dummy_sdp);
    if (status != PJ_SUCCESS) {
      app_perror(THIS_FILE, "Error parsing dummy SDP", status);
      return status;
    }
  }
  return PJ_SUCCESS;
}

static int get_word(pj_str_t *source, pj_str_t *result, char delimeter) {
  int size = -1;
  char *tmp;

  if ((tmp = pj_strchr(source, (int) delimeter)) != NULL) {
    size = (tmp - (source->ptr));

    // Trick to use strncpy. Need a pj_str_t type.
    pj_str_t ori_tmp;
    ori_tmp.slen = size;
    ori_tmp.ptr = source->ptr; 
    result->slen = size + 1;

    result->ptr = (char*) pj_pool_alloc(app.pool, size + 1); 
    pj_strncpy(result, &ori_tmp, size);
    *((result->ptr) + (size + 1)) = (char)0;  
        
    // Moving forward the source.
    // No worry to free the memory. Pool will do it automated.
    source->slen -= (size + 1);
    source->ptr += (size + 1);
  }  

  return size;
}

static int get_headerName(pj_str_t  *source, pj_str_t *result) {
  return get_word(source, result, '*');
}

static int get_headerValue(pj_str_t  *source, pj_str_t *result) {
  return get_word(source, result, '?');
}


static void usage(void)
{
  puts("Usage: img [options]");
  puts("");
  puts("Options:");
  puts(" --transport, -t <transport>                         \"tcp|udp\"");
  puts(" --uri,       -u <uri>                               \"uri\"");
  puts(" --parameter, -p <name> <value>                      \"string\"");
  puts(" --header,    -h <header> <value>                    \"string\"");
  puts(" --multipart, -m <type> <subtype>                    \"string string\"");
  puts("                 <head1*val1?...headn*valn?>         \"string*string?...\"");
  puts("                 <filetype> <file>                   \"<'binary'|'text'> file\"");
  puts(" --boundary,  -b <boundary>                          \"string\"");
  puts("");
}

static pj_status_t parse_options(int argc, char *argv[])
{
    struct pj_getopt_option long_options[] = {
	{ "transport",	    1, 0, 't' },
	{ "uri",	    1, 0, 'u' },
	{ "parameter",	    1, 0, 'p' },
	{ "header",	    1, 0, 'h' },
	{ "multipart",	    1, 0, 'm' },
	{ "boundary",	    1, 0, 'b' },
	{ NULL, 0, 0, 0 },
    };

    int c;
    int option_index;
    pj_status_t status;

    // Parse options.
    pj_optind = 0;
    while((c=pj_getopt_long(argc,argv, "t:u:p:h:m:b:", 
			    long_options, &option_index))!=-1) 
      {
	switch (c) {
	case 't':
	  {
	    if (!app.opt.b_transport)
	      {
		app.opt.b_transport = PJ_TRUE;
		pj_str_t transport = pj_str((char*)pj_optarg);
		
		if ( (app.opt.b_tcp = ((pj_stricmp2(&transport, "tcp") == 0) ? PJ_TRUE : PJ_FALSE)) ||
		     (app.opt.b_udp = ((pj_stricmp2(&transport, "udp") == 0) ? PJ_TRUE : PJ_FALSE)) )
		  {
		    PJ_LOG(1,(THIS_FILE, "Founded -t <transport>=%s.", transport.ptr));
		  } else {
		  PJ_LOG(1,(THIS_FILE, "-t not valid value=\"%s\".", transport.ptr));
		  usage();
		  return -1;
		}
	      } else {
	      PJ_LOG(1,(THIS_FILE, "-t already defined"));
	      usage();
	      return -1;
	    }
	  }
	  break;	  
	  
	case 'u':
	  {
	    if (!app.opt.b_uri)
	      {
		app.opt.b_uri = PJ_TRUE;
		pj_str_t uri = pj_str((char*)pj_optarg);
		PJ_LOG(1,(THIS_FILE, "Founded -u <uri>=%s",
			  uri.ptr));
		
		if (verify_sip_url(uri.ptr) != PJ_SUCCESS) {
		  PJ_LOG(1,(THIS_FILE, "Invalid SIP URI %s", uri.ptr));
		  return -1;
		}		

		pj_strdup(app.pool, &app.opt.uri, &uri);
		PJ_LOG(1,(THIS_FILE, "<uri>=%s",
			  app.opt.uri.ptr));
	      } else {
	      PJ_LOG(1,(THIS_FILE, "-u already defined"));
	      usage();
	      return -1;
	    }
	  }
	  break;

	case 'p':
	  {
	    {
	      app.opt.b_uriparams_list = PJ_TRUE;
	      pj_str_t name = pj_str((char*)pj_optarg);
	      pj_str_t value = pj_str((char*)argv[pj_optind++]);
	      PJ_LOG(1,(THIS_FILE, "Founded -p <name>=%s <value>=%s",
			name.ptr, value.ptr));
	      	      
	      // Inserting the param into a list.
	      pjsip_param *param;
	      param = PJ_POOL_ALLOC_T(app.pool, pjsip_param);
	      param->name = name;
	      param->value = value;
	      pj_list_push_back(&app.opt.uriparams_list, param); 
	      PJ_LOG(1,(THIS_FILE, "Inserted -p <name>=%s <value>=%s",
			param->name.ptr, param->value.ptr));
	    }
	  }
	  break; 


	case 'h':
	  {
	    {
	      app.opt.b_hdr_list = PJ_TRUE;	      
	      pj_str_t header = pj_str((char*)pj_optarg);
	      pj_str_t value = pj_str((char*)argv[pj_optind++]);
	      PJ_LOG(1,(THIS_FILE, "Founded -h <header>=%s <value>=%s",
			header.ptr, value.ptr));
	      	      
	      // Inserting the header into hdr_list.
	      // Create the header.
	      pjsip_generic_string_hdr *h;
	      h = pjsip_generic_string_hdr_create(app.pool, &header, &value);
	      pj_list_push_back(&app.opt.hdr_list, h);
	      PJ_LOG(1,(THIS_FILE, "Inserted -h <header>=%s <value>=%s",
			h->name.ptr, h->hvalue.ptr));
	    }
	  }
	  break; 

	case 'm':
	  {
	    if (app.opt.b_boundary) {	      
	      pj_str_t type = pj_str((char*)pj_optarg);
	      pj_str_t subtype = pj_str((char*)argv[pj_optind++]);
	      pj_str_t headers = pj_str((char*)argv[pj_optind++]);
	      pj_str_t filetype = pj_str((char*)argv[pj_optind++]);
	      pj_str_t file = pj_str((char*)argv[pj_optind++]);
	      
	      PJ_LOG(1,(THIS_FILE, "Founded -m <type>=%s <subtype>=%s <headers>=%s <filetype>=%s <file>=%s",
			type.ptr, subtype.ptr, headers.ptr, filetype.ptr, file.ptr));

	      if (app.opt.b_single_body) {
		app.opt.b_single_body = PJ_FALSE;
		app.opt.b_multipart_body = PJ_TRUE;
		app.opt.body = pjsip_multipart_create(app.pool, NULL, &app.opt.boundary);
		
		// Adding the sdp in the multipart mode.
		pjsip_multipart_part *part;
		part = pjsip_multipart_create_part(app.pool);
		part->body =  pjsip_msg_body_create(app.pool, &mime_application, &mime_sdp, &dummy_sdp_str);
		status =  pjsip_multipart_add_part(app.pool, app.opt.body, part);
		PJ_ASSERT_RETURN(status == PJ_SUCCESS, 1);
	      }
	      
	      int binary = (pj_strcmp2(&filetype, "binary") == 0);
	      int text = (pj_strcmp2(&filetype, "text")   == 0);
	      if (!(binary || text)) {
		app_perror(THIS_FILE, "filetype must be either 'binary' or 'text'.", -1);
		usage();
		return -1;
	      }	      
	      
	      // Adding the file.
	      pj_oshandle_t f;
	      if (pj_file_exists(file.ptr)) {
		status = pj_file_open(app.pool, file.ptr, PJ_O_RDONLY, &f);
		if (status != PJ_SUCCESS) {
		  app_perror(THIS_FILE, "Unable to open the file", status);
		  return -1;
		}
	      } else {
		app_perror(THIS_FILE, "File does not exist", status);
		return -1;
	      }


	      {
		pj_str_t buffer;
		
		// Binary file. Appropiate to SS7 contents.
		if (binary) {
		  int k = 0;
		  int read = 1;
		  long hexs[MAX_FILE_SIZE];
		  //unsigned int hexs[MAX_FILE_SIZE] TODO
		  while ((k < MAX_FILE_SIZE) && (read == 1)) {
		    read = fscanf(f, "%lX", &hexs[k]);
		    if (read == 1) {
		      k++;
		    }
		    else {
		      break;
		    }
		  }
		  buffer.slen = k;
		  buffer.ptr = (char*) pj_pool_alloc(app.pool, buffer.slen);
		  char *tmp = buffer.ptr;
		  PJ_LOG(3,(THIS_FILE, "Binary file. Hexadecimal buffer="));
		  for (k=0; k < buffer.slen; k++) {
		    *tmp = hexs[k];
		    tmp++;
		    PJ_LOG(3,(THIS_FILE, "%i \t \"%.2lX\"", k, hexs[k]));
		  }
		}
		
		// Normal text/plain file.
		if (text) {
		  buffer.slen = MAX_FILE_SIZE;
		  buffer.ptr = (char*) pj_pool_alloc(app.pool, buffer.slen); 
		  status = pj_file_read(f, buffer.ptr, &buffer.slen);
		  if (status != PJ_SUCCESS) {
		    app_perror(THIS_FILE, "Unable to read the file", status);
		    return -1;
		  }
		  PJ_LOG(3,(THIS_FILE, "Text file. Normal buffer=\n\"%s\"", buffer.ptr));
		}
		

		status = pj_file_close(f);
		if (status != PJ_SUCCESS) {
		  app_perror(THIS_FILE, "Unable to close the file.", status);
		  return -1;
		}
	      
		// Adding multipart.
		pjsip_multipart_part *part;
		part = pjsip_multipart_create_part(app.pool);
		part->body =  pjsip_msg_body_create(app.pool, &type, &subtype, &buffer);
		
		// Parse and create the multipart headers.
		{
		  PJ_LOG(3,(THIS_FILE, "headers=\n\"%s\"", headers));
		  if (pj_strcmp2(&headers, "empty")) {
		    pj_str_t htext;
		    pj_str_t hvalue;
		    int retName;
		    int retValue = 1; //trick
		    // TODO strtok would be easier? lmartin
		    while ((headers.slen != 0) &&
			   (retValue > 0) &&
			   ((retName = get_headerName(&headers, &htext)) > 0)) {
		      PJ_LOG(3,(THIS_FILE, "htext=\"%s\"", htext.ptr));
		      if ((retValue = get_headerValue(&headers, &hvalue)) > 0) {
			PJ_LOG(3,(THIS_FILE, "hvalue\"%s\"", hvalue.ptr));
			pjsip_generic_string_hdr *h;
			h = pjsip_generic_string_hdr_create(app.pool, &htext, &hvalue);
			pj_list_push_back(&part->hdr, h);
		      }
		    }
		    if (retName > 0) {
		      if (retValue > 0) {
		      } else {
			app_perror(THIS_FILE, "Unable to parse the value of the multipart header.", -1);
			return -1;
		      }
		    } else {
		      app_perror(THIS_FILE, "Unable to parse the header of the multipart.", -1);
		      return -1;
		    }
		  }
		}
	      
		status =  pjsip_multipart_add_part(app.pool, app.opt.body, part);
		PJ_ASSERT_RETURN(status == PJ_SUCCESS, 1);
	      }
	      
	    } else {
	      PJ_LOG(1,(THIS_FILE, "Error: you have to set the -b option before the -m option."));
	      usage();
	      return -1;
	    }
	  }
	  break;	  

	case 'b':
	  {
	    if (!app.opt.b_boundary)
	      {
		app.opt.b_boundary = PJ_TRUE;
		pj_str_t boundary = pj_str((char*)pj_optarg);
		PJ_LOG(1,(THIS_FILE, "Founded -b %s",
			  boundary.ptr));
		pj_strdup(app.pool, &app.opt.boundary, &boundary);
	      }
	    else
	      {
		PJ_LOG(1,(THIS_FILE, "-b already defined"));
		usage();
		return -1;
	      }
	  }
	  break;
	  
	default:
	  PJ_LOG(1,(THIS_FILE, "Error: Invalid argument."));
	  usage();
	  return -1;
	}
    }

    if (pj_optind != argc) {
      PJ_LOG(1,(THIS_FILE, "Error: unknown option %s.", argv[pj_optind]));
      usage();
      return -1;
    }

    if (!app.opt.b_transport) {
      PJ_LOG(1,(THIS_FILE, "Error: -t option is mandatory."));
      usage();
      return -1;
    }

    if (!app.opt.b_uri) {
      PJ_LOG(1,(THIS_FILE, "Error: -u option is mandatory."));
      usage();
      return -1;
    }

    if (app.opt.b_single_body) {
      if (app.opt.b_boundary) {      
	PJ_LOG(1,(THIS_FILE, "Error: -b option is not necessary while multipart is present."));
	usage();
	return -1;
      }
    }    
    
    return PJ_SUCCESS;
}

static pj_status_t init_options()
{
  app.g_complete = 0;

  app.opt.b_transport = PJ_FALSE;
  app.opt.b_tcp = PJ_FALSE;
  app.opt.b_udp = PJ_FALSE;

  app.opt.uri;
  app.opt.b_uri = PJ_FALSE;

  pj_list_init(&app.opt.uriparams_list);
  app.opt.b_uriparams_list = PJ_FALSE;
  
  app.opt.boundary;
  app.opt.b_boundary = PJ_FALSE;

  pj_list_init(&app.opt.hdr_list);
  app.opt.b_hdr_list = PJ_FALSE;
  
  app.opt.body;
  app.opt.b_single_body = PJ_TRUE;  
  app.opt.b_multipart_body = PJ_FALSE;
  pj_status_t status;
    
  // Must init PJLIB first.
  status = pj_init();
  PJ_ASSERT_RETURN(status == PJ_SUCCESS, 1);
    
  // Then init PJLIB-UTIL.
  status = pjlib_util_init();
  PJ_ASSERT_RETURN(status == PJ_SUCCESS, 1);
      
  // Must create a pool factory before we can allocate any memory.
  pj_caching_pool_init(&app.cp, &pj_pool_factory_default_policy, 0);
  
  // Creating another pool for random needs.
  app.pool = pj_pool_create(&app.cp.factory, "app", POOL_SIZE, POOL_SIZE, NULL);
  
  // Create global endpoint.  
  status = pjsip_endpt_create(&app.cp.factory, pj_gethostname()->ptr, &app.g_endpt);
  PJ_ASSERT_RETURN(status == PJ_SUCCESS, status);

  verify_scp();

  return PJ_SUCCESS;
}


// Sending the INVITE.
static pj_status_t run()
{
  pj_status_t status;
  
  {
    pj_sockaddr addr;    
    pj_sockaddr_init(AF, &addr, NULL, (pj_uint16_t)SIP_PORT);
    if (AF == pj_AF_INET()) {
      if (app.opt.b_tcp) {
	status = pjsip_tcp_transport_start(app.g_endpt, &addr.ipv4, 1, NULL);
      } else {
	status = pjsip_udp_transport_start(app.g_endpt, &addr.ipv4, NULL, 1, NULL);
      }      
    } else if (AF == pj_AF_INET6()) {
      if (app.opt.b_tcp) {
	status = pjsip_tcp_transport_start6(app.g_endpt, &addr.ipv6, 1, NULL);
      } else {
	status = pjsip_udp_transport_start6(app.g_endpt, &addr.ipv6, NULL, 1, NULL);
      }
    }
    else {
      status = PJ_EAFNOTSUP;
    }    
    if (status != PJ_SUCCESS) {
      app_perror(THIS_FILE, "Unable to start transport", status);
      return 1;
    }
  }

  // Init transaction layer.
  status = pjsip_tsx_layer_init_module(app.g_endpt);
  PJ_ASSERT_RETURN(status == PJ_SUCCESS, 1);
          
  // Initialize UA layer module.
  status = pjsip_ua_init_module(app.g_endpt, NULL );
  PJ_ASSERT_RETURN(status == PJ_SUCCESS, 1);
      
  {
    pjsip_inv_callback inv_cb;
      
    // Init the callback for INVITE session.
    pj_bzero(&inv_cb, sizeof(inv_cb));
    inv_cb.on_state_changed = &call_on_state_changed;
    inv_cb.on_new_session = &call_on_forked;
    
    // Initialize invite session module.
    status = pjsip_inv_usage_init(app.g_endpt, &inv_cb);
    PJ_ASSERT_RETURN(status == PJ_SUCCESS, 1);
  }
      
  // Initialize 100rel support.
  status = pjsip_100rel_init_module(app.g_endpt);
  PJ_ASSERT_RETURN(status == PJ_SUCCESS, status);

  {
    pj_sockaddr hostaddr;
    char hostip[PJ_INET6_ADDRSTRLEN+2];
    char temp[80];
    pj_str_t local_uri;
    
    if (pj_gethostip(AF, &hostaddr) != PJ_SUCCESS) {
      app_perror(THIS_FILE, "Unable to retrieve local host IP", status);
      return 1;
    }
    pj_sockaddr_print(&hostaddr, hostip, sizeof(hostip), 2);
    
    pj_ansi_sprintf(temp, "<sip:lmartin@%s:%d>", hostip, SIP_PORT);
    local_uri = pj_str(temp);

    // Create UAC dialog.
    status = pjsip_dlg_create_uac( pjsip_ua_instance(), 
				   &local_uri,    // local URI
				   &local_uri,    // local target
				   &app.opt.uri,  // remote URI
				   &app.opt.uri,  // remote Contact
				   &app.dlg);    // dialog
    
    if (status != PJ_SUCCESS) {
      app_perror(THIS_FILE, "Unable to create UAC dialog", status);
      return 1;
    }
    
    status = pjsip_inv_create_uac(app.dlg, NULL, 0, &app.g_inv);
    PJ_ASSERT_RETURN(status == PJ_SUCCESS, 1);
        
    // Create initial INVITE request.
    {
      status = pjsip_inv_invite(app.g_inv, &app.tdata);
      PJ_ASSERT_RETURN(status == PJ_SUCCESS, 1);
    }
        
    // Adding the transport method to the message.         
    {  
      pjsip_sip_uri *uri;
      uri=(pjsip_sip_uri*)pjsip_uri_get_uri(app.tdata->msg->line.req.uri);
      uri->transport_param = pj_str((app.opt.b_tcp) ? "tcp" : "udp");     
      // Adding optional uri parameters, if any.
      {
	if (app.opt.b_uriparams_list) {
	  pj_list_merge_first(&uri->other_param, &app.opt.uriparams_list);
	}
      }     
    }
    
    // Generating Call-ID
    {
      {
	// Initialization the random string.
        pj_time_val now;
	pj_gettimeofday(&now);
	pj_srand((unsigned)(now.msec*now.sec)); // Shake it
	pj_srand((unsigned)(now.msec*now.sec)); // Shake it twice

	pj_str_t random;
	random.slen = CALL_ID_RSIZE;
	random.ptr = (char*) pj_pool_alloc(app.pool, random.slen);
	random.ptr = pj_create_random_string(random.ptr, random.slen);      
      
	// Call-ID will be "random" + "@" + "host".
	pj_str_t call_id;
	call_id.slen = CALL_ID_RSIZE + strlen(hostip) + 1;
	call_id.ptr = (char*) pj_pool_alloc(app.pool, call_id.slen);	       
	pj_strcpy2(&call_id, random.ptr);
	pj_strcat2(&call_id, "@");
	pj_strcat2(&call_id, hostip);
	call_id.ptr[call_id.slen] = '\0';

	// Finding Call-ID and setting the new value.	
	pjsip_cid_hdr *hdr;
	hdr = pjsip_msg_find_hdr(app.tdata->msg, PJSIP_H_CALL_ID, NULL);
	hdr->id = call_id;
      }
    }


    // Adding headers, if any.
    {
      if (app.opt.b_hdr_list) {
	pjsip_hdr *p_hdr_list = &app.opt.hdr_list;	  
	if (p_hdr_list) {
	  const pjsip_hdr *hdr = p_hdr_list->next;
	  while (hdr != p_hdr_list) {
	    pjsip_msg_add_hdr(app.tdata->msg,
			      (pjsip_hdr*) pjsip_hdr_clone(app.pool, hdr) );
	    hdr = hdr->next;
	  }
	}	  
      }
    }
    
    // Adding body.    
    {
      // Single body. Just adding the scp.
      if (app.opt.b_single_body) {
	app.tdata->msg->body = pjsip_msg_body_create(app.pool,
						     &mime_application, &mime_sdp,
						     &dummy_sdp_str);
	// Multipart body. Adding the scp + the parsed multiparts.
      } else {
	app.tdata->msg->body = app.opt.body;
      }
    }
        
    // Sending the INVITE.
    status = pjsip_inv_send_msg(app.g_inv, app.tdata);
    PJ_ASSERT_RETURN(status == PJ_SUCCESS, 1);
    
  }

  // Loop until one call is completed.
  for (;!app.g_complete;) {
    pj_time_val timeout = {0, 5};
    pjsip_endpt_handle_events(app.g_endpt, &timeout);
  }

  // On exit, dump current memory usage.
  dump_pool_usage(THIS_FILE, &app.cp);

  return PJ_SUCCESS;
}

// Callback when INVITE session state has changed.
static void call_on_state_changed( pjsip_inv_session *inv, 
				   pjsip_event *e)
{  
  PJ_UNUSED_ARG(e);
  if (inv->state == PJSIP_INV_STATE_DISCONNECTED) {
    PJ_LOG(3,(THIS_FILE, "Call DISCONNECTED [reason=%d (%s)]",
	      inv->cause,
	      pjsip_get_status_text(inv->cause)->ptr));    
    PJ_LOG(3,(THIS_FILE, "One call completed, application quitting..."));
    app.g_complete = 1;    
  } else {
    PJ_LOG(3,(THIS_FILE, "Call state changed to %s",
	      pjsip_inv_state_name(inv->state)));
  }
}

// This callback is called when dialog has forked.
static void call_on_forked(pjsip_inv_session *inv, pjsip_event *e)
{
  PJ_UNUSED_ARG(inv);
  PJ_UNUSED_ARG(e);
}

// Callback to be called to handle incoming requests outside dialogs.
static pj_bool_t on_rx_request( pjsip_rx_data *rdata )
{
  PJ_UNUSED_ARG(rdata);
  return PJ_TRUE;
}
