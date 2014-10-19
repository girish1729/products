#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <err.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/pfvar.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <syslog.h>
#include <errno.h>
#include <signal.h>
#include <regex.h>
#include <sqlite3.h>
#include <sys/queue.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <getopt.h>
#include <netdb.h>


#include <spf2/spf.h>
/* XXX SPF querying */

#define TRUE 1
#define FALSE 0

#define FREE(x, f) do { if ((x)) (f)((x)); (x) = NULL; } while(0)
#define FREE_REQUEST(x) FREE((x), SPF_request_free)
#define FREE_RESPONSE(x) FREE((x), SPF_response_free)

#define CONTINUE_ERROR do { res = 255; continue; } while(0)
#define WARN_ERROR do { res = 255; } while(0)
#define FAIL_ERROR do { res = 255; goto error; } while(0)

#define RESIZE_RESULT(n) do { \
	if (result == NULL) { \
		result_len = 256 + n; \
		result = malloc(result_len); \
		result[0] = '\0'; \
	} \
	else if (strlen(result) + n >= result_len) { \
		result_len = result_len + (result_len >> 1) + 8 + n; \
		result = realloc(result, result_len); \
	} \
} while(0)
#define APPEND_RESULT(n) do { \
	partial_result = SPF_strresult(n); \
	RESIZE_RESULT(strlen(partial_result)); \
	strlcat(result, partial_result, 1024); \
} while(0)

#define X_OR_EMPTY(x) ((x) ? (x) : "")
/* Some globals */
extern char 	envip[1024], 
	helostring[1024],
	envfrom[1024];


	static void
response_print_errors(const char *context,
		SPF_response_t *spf_response, SPF_errcode_t err)
{
	SPF_error_t             *spf_error;
	int                              i;

	syslog(LOG_INFO,"StartError\n");

	if (context != NULL)
		syslog(LOG_INFO,"Context: %s\n", context);
	if (err != SPF_E_SUCCESS)
		syslog(LOG_INFO,"ErrorCode: (%d) %s\n", err, SPF_strerror(err));

	if (spf_response != NULL) {
		for (i = 0; i < SPF_response_messages(spf_response); i++) {
			spf_error = SPF_response_message(spf_response, i);
			syslog(LOG_INFO, "%s: %s%s\n",
					SPF_error_errorp(spf_error) ? "Error" : "Warning",
					// SPF_error_code(spf_error),
					// SPF_strerror(SPF_error_code(spf_error)),
					((SPF_error_errorp(spf_error) && (!err))
					 ? "[UNRETURNED] "
					 : ""),
					SPF_error_message(spf_error) );
		}
	}
	else {
		syslog(LOG_INFO,"libspf2 gave a NULL spf_response\n");
	}
	syslog(LOG_INFO,"EndError\n");
}

	static void
response_print(const char *context, SPF_response_t *spf_response)
{
	syslog(LOG_INFO,"--vv--\n");
	syslog(LOG_INFO,"Context: %s\n", context);
	if (spf_response == NULL) {
		syslog(LOG_INFO,"NULL RESPONSE!\n");
	}
	else {
		syslog(LOG_INFO,"Response result: %s\n",
				SPF_strresult(SPF_response_result(spf_response)));
		syslog(LOG_INFO,"Response reason: %s\n",
				SPF_strreason(SPF_response_reason(spf_response)));
		syslog(LOG_INFO,"Response err: %s\n",
				SPF_strerror(SPF_response_errcode(spf_response)));
		response_print_errors(NULL, spf_response,
				SPF_response_errcode(spf_response));
	}
	syslog(LOG_INFO,"--^^--\n");
}

typedef
struct SPF_client_options_struct {
	// void         *hook;
	char            *localpolicy;
	const char      *explanation;
	const char      *fallback;
	const char      *rec_dom;
	int              use_trusted;
	int                      max_lookup;
	int                      sanitize;
	int                      debug;
} SPF_client_options_t;

typedef
struct SPF_client_request_struct {
	char            *ip;
	char            *sender;
	char            *helo;
	char            *rcpt_to;
} SPF_client_request_t;

int spfquery(void)
{
	SPF_client_options_t    *opts;
	SPF_client_request_t    *req;

	SPF_server_t    *spf_server = NULL;
	SPF_request_t   *spf_request = NULL;
	SPF_response_t  *spf_response = NULL;
	SPF_response_t  *spf_response_2mx = NULL;
	SPF_response_t  *spf_response_fallback = NULL;
	SPF_errcode_t    err;

	int                      opt_keep_comments = 0;

	FILE                    *fin;
	char                     in_line[4096];
	char                    *p, *p_end;
	int                      done_once;

	int                              res = 0;

	const char              *partial_result;
	char                    *result = NULL;
	int                              result_len = 0;

	opts = (SPF_client_options_t *)malloc(sizeof(SPF_client_options_t));
	memset(opts, 0, sizeof(SPF_client_options_t));

	req = (SPF_client_request_t *)malloc(sizeof(SPF_client_request_t));
	memset(req, 0, sizeof(SPF_client_request_t));

	opts->rec_dom = "spfquery";

	req->ip = envip;
	req->sender = envfrom;
	req->helo = helostring;

	/*
	 * set up the SPF configuration
	 */

	spf_server = SPF_server_new(SPF_DNS_CACHE, opts->debug);

	if ( opts->rec_dom )
		SPF_server_set_rec_dom( spf_server, opts->rec_dom );
	if ( opts->sanitize )
		SPF_server_set_sanitize( spf_server, opts->sanitize );
	if ( opts->max_lookup )
		SPF_server_set_max_dns_mech(spf_server, opts->max_lookup);

	if (opts->localpolicy) {
		err = SPF_server_set_localpolicy( spf_server, opts->localpolicy, opts->use_trusted, &spf_response);
		if ( err ) {
			response_print_errors("Error setting local policy",
					spf_response, err);
			WARN_ERROR;
		}
		FREE_RESPONSE(spf_response);
	}


	if ( opts->explanation ) {
		err = SPF_server_set_explanation( spf_server, opts->explanation, &spf_response );
		if ( err ) {
			response_print_errors("Error setting default explanation",
					spf_response, err);
			WARN_ERROR;
		}
		FREE_RESPONSE(spf_response);
	}
	fin = NULL;

	if ((req->ip == NULL) ||
			(req->sender == NULL && req->helo == NULL) ) {
		FAIL_ERROR;
	}


	done_once = FALSE;

	while ( TRUE ) {
		if ( fin ) {
			if ( fgets( in_line, sizeof( in_line ), fin ) == NULL )
				break;

			in_line[strcspn(in_line, "\r\n")] = '\0';
			p = in_line;

			p += strspn( p, " \t\n" );
			{
				if ( *p == '\0' || *p == '#' ) {
					if ( opt_keep_comments )
						syslog(LOG_INFO, "%s\n", in_line );
					continue;
				}
			}
			req->ip = p;
			p += strcspn( p, " \t\n" );
			*p++ = '\0';

			p += strspn( p, " \t\n" );
			req->sender = p;
			p += strcspn( p, " \t\n" );
			*p++ = '\0';

			p += strspn( p, " \t\n" );
			req->helo = p;
			p += strcspn( p, " \t\n" );
			*p++ = '\0';

			p += strspn( p, " \t\n" );
			req->rcpt_to = p;
			p += strcspn( p, " \t\n" );
			*p++ = '\0';
		}
		else {
			if ( done_once )
				break;
			done_once = TRUE;
		}

		/* We have to do this here else we leak on CONTINUE_ERROR */
		FREE_REQUEST(spf_request);
		FREE_RESPONSE(spf_response);

		spf_request = SPF_request_new(spf_server);

		if (SPF_request_set_ipv4_str(spf_request, req->ip)
				&& SPF_request_set_ipv6_str(spf_request, req->ip)) {
			syslog(LOG_INFO, "Invalid IP address.\n" );
			CONTINUE_ERROR;
		}

		if (req->helo) {
			if (SPF_request_set_helo_dom( spf_request, req->helo ) ) {
				syslog(LOG_INFO, "Invalid HELO domain.\n" );
				CONTINUE_ERROR;
			}
		}

		if (SPF_request_set_env_from( spf_request, req->sender ) ) {
			syslog(LOG_INFO, "Invalid envelope from address.\n" );
			CONTINUE_ERROR;
		}

		err = SPF_request_query_mailfrom(spf_request, &spf_response);
		if (opts->debug)
			response_print("Main query", spf_response);
		if (err) {
			response_print_errors("Failed to query MAIL-FROM",
					spf_response, err);
			CONTINUE_ERROR;
		}

		if (result != NULL)
			result[0] = '\0';
		APPEND_RESULT(SPF_response_result(spf_response));

		if (req->rcpt_to != NULL  && *req->rcpt_to != '\0' ) {
			p = req->rcpt_to;
			p_end = p + strcspn(p, ",;");

			/* This is some incarnation of 2mx mode. */
			while (SPF_response_result(spf_response)!=SPF_RESULT_PASS) {
				if (*p_end)
					*p_end = '\0';
				else
					p_end = NULL;   /* Note this is last rcpt */

				err = SPF_request_query_rcptto(spf_request,
						&spf_response_2mx, p);
				if (opts->debug)
					response_print("2mx query", spf_response_2mx);
				if (err) {
					response_print_errors("Failed to query RCPT-TO",
							spf_response, err);
					CONTINUE_ERROR;
				}

				/* append the result */
				APPEND_RESULT(SPF_response_result(spf_response_2mx));

				spf_response = SPF_response_combine(spf_response,
						spf_response_2mx);

				if (!p_end)
					break;
				p = p_end + 1;
			}
		}

		/* We now have an option to call SPF_request_query_fallback */
		if (opts->fallback) {
			err = SPF_request_query_fallback(spf_request,
					&spf_response_fallback, opts->fallback);
			if (opts->debug)
				response_print("fallback query", spf_response_fallback);
			if (err) {
				response_print_errors("Failed to query best-guess",
						spf_response_fallback, err);
				CONTINUE_ERROR;
			}

			/* append the result */
			APPEND_RESULT(SPF_response_result(spf_response_fallback));

			spf_response = SPF_response_combine(spf_response,
					spf_response_fallback);
		}

		syslog(LOG_INFO, "%s\n%s\n%s\n%s\n",
				result,
				X_OR_EMPTY(SPF_response_get_smtp_comment(spf_response)),
				X_OR_EMPTY(SPF_response_get_header_comment(spf_response)),
				X_OR_EMPTY(SPF_response_get_received_spf(spf_response))
		      );

		res = SPF_response_result(spf_response);

		fflush(stdout);
	}

error:
	FREE(result, free);
	FREE_RESPONSE(spf_response);
	FREE_REQUEST(spf_request);
	FREE(spf_server, SPF_server_free);

	FREE(req, free);
	FREE(opts, free);


	return res;
}


