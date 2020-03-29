#include <vector>
#include <map>
#include <spdlog/formatter.h>
#include "utils.hpp"
#include "https_socket.hpp"

namespace ssl = boost::asio::ssl;

namespace crithit
{
	using namespace fmt::literals;

	void https_socket::send_https_data()
	{
		beast::get_lowest_layer( tcp_stream_ ).expires_after( std::chrono::milliseconds( args_.max_timeout_milli ) );
		if( is_post_request ) {
			http::async_write( tcp_stream_, post_request_, beast::bind_front_handler( &https_socket::on_data_sent, this ) );
		} else {
			http::async_write( tcp_stream_, get_request_, beast::bind_front_handler( &https_socket::on_data_sent, this ) );
		}
	}

	void https_socket::on_data_sent( beast::error_code ec, std::size_t const bytes_sent )
	{
		if( ec ) resend_https_request();
		else receive_data();
	}

	void https_socket::receive_data()
	{
		beast::get_lowest_layer( tcp_stream_ ).expires_after( std::chrono::milliseconds( args_.max_receiving_timeout ) );
		http::async_read( tcp_stream_, buffer_, response_, beast::bind_front_handler( &https_socket::on_data_received, this ) );
	}

	void https_socket::send_post_request()
	{
		is_post_request = true;
		post_data_size = 0;
		create_request_data( "POST" );
		beast::get_lowest_layer( tcp_stream_ ).expires_never();
		send_https_data();
	}

	void https_socket::start_connect( std::string && url )
	{
		is_post_request = false;
		connect_count_ = send_count_ = 0;
		current_url_ = std::move( url );
		uri u{ current_url_ };
		host_ = u.host();
		path_ = u.path();

		create_request_data( "GET" );
		process_proxy();
	}

	void https_socket::set_remove_iterator( custom_http_socket * parent, std::list<std::unique_ptr<https_socket>>::iterator iter )
	{
		parent_ = parent;
		iter_ = iter;
	}

	void https_socket::on_host_resolved( beast::error_code ec, tcp::resolver::results_type result )
	{
		if( ec ) disconnect();
		else {
			result_ = std::move( result );
			connect();
		}
	}

	void https_socket::connect()
	{
		beast::get_lowest_layer( tcp_stream_ ).expires_after( std::chrono::milliseconds( args_.max_timeout_milli ) );
		beast::get_lowest_layer( tcp_stream_ ).async_connect( result_, beast::bind_front_handler( &https_socket::on_connected,
			this ) );
	}

	void https_socket::reconnect()
	{
		++connect_count_;
		if( connect_count_ >= args_.max_reconnect ) disconnect();
		else connect();
	}

	void https_socket::on_connected( beast::error_code ec, tcp::resolver::results_type::endpoint_type )
	{
		if( ec ) reconnect();
		else perform_handshake();
	}

	void https_socket::process_result_signature( std::string const & response_body )
	{
		// if we're not checking for signatures
		if( !runtime_info_.is_using_signature ) return;
		process_string_signature( runtime_info_.signatures.string_search, response_body, current_url_ );
		process_regex_signature( runtime_info_.signatures.regex_search, response_body, current_url_ );
	}

	void https_socket::process_proxy( std::string const & port )
	{
		resolver_.async_resolve( host_, port, beast::bind_front_handler( &https_socket::on_host_resolved, this ) );
	}

	void https_socket::create_request_data( std::string const & method )
	{
		if( method == "GET" ) {
			get_request_.method( beast::http::verb::get );
			get_request_.version( 11 );
			get_request_.target( path_ );
			get_request_.set( beast::http::field::host, host_ + ":443" );
			get_request_.set( beast::http::field::accept, "*/*" );
			get_request_.set( beast::http::field::connection, "keep-alive" );
			get_request_.set( beast::http::field::cache_control, "no-cache" );
			get_request_.set( beast::http::field::user_agent, get_random_agent() );
		} else {
			post_request_.method( beast::http::verb::post );
			post_request_.version( 11 );
			post_request_.target( path_ );
			post_request_.set( beast::http::field::host, host_ + ":443" );
			post_request_.set( beast::http::field::accept, "*/*" );
			post_request_.set( beast::http::field::connection, "keep-alive" );
			post_request_.set( beast::http::field::cache_control, "no-cache" );
			post_request_.set( beast::http::field::user_agent, get_random_agent() );
			post_request_.set( beast::http::field::content_type, "text/plain" );
			post_request_.body() = "{}={}&{}={}"_format( random_string( 5 ), random_string( 10 ),
				random_string( 5 ), random_string( 11 ) );
			post_request_.prepare_payload();
			post_data_size = post_request_.body().size();
		}
	}

	void https_socket::perform_handshake()
	{
		tcp_stream_.async_handshake( ssl::stream_base::client,
			beast::bind_front_handler( &https_socket::on_handshook, this ) );
	}

	void https_socket::on_handshook( beast::error_code ec )
	{
		if( ec ) {
			++handshake_count_;
			if( handshake_count_ >= args_.max_send_count ) disconnect();
			else perform_handshake();
		} else send_https_data();
	}


	https_socket::https_socket( net::io_context & io_context, command_line_args const & args,
		runtime_list_information const & runtime_info ) :io_{ io_context }, args_{ args },
		runtime_info_{ runtime_info }, resolver_{ net::make_strand( io_ ) }, parent_{},
		ctx_{ create_ssl_context() }, tcp_stream_{ net::make_strand( io_ ), ctx_ },
		report_408{ !status_found_in( 408, request_handler::exempted_statuses ) &&
			status_found_in( 408, request_handler::accepted_statuses ) }
	{
	}

	https_socket::~https_socket()
	{
	}

	void https_socket::server_error()
	{
		if( report_408 ) display_result( current_url_, "", 408, path_, out_file_ );
	}

	void https_socket::set_output_file( std::shared_ptr<std::ostream> outfile )
	{
		out_file_ = outfile;
	}

	ssl::context create_ssl_context()
	{
		ssl::context context_{ ssl::context::tlsv12 };
		context_.set_default_verify_paths();
		context_.set_verify_mode( ssl::verify_none );
		return context_;
	}

	void https_socket::on_data_received( beast::error_code ec, std::size_t const bytes_received )
	{
		if( ec ) {
			server_error();
			disconnect();
			return;
		}

		int const status_code = response_.result_int();
		// if status_code is found in exempted codes, do nothing, just flow down to the call to disconnect();
		if( status_found_in( status_code, request_handler::exempted_statuses ) );
		else if( status_found_in( status_code, request_handler::accepted_statuses ) ) {
			bool const exception_present = in_exception_list( runtime_info_.exception_list, response_.body() );
			if( !is_post_request && status_code == 200 ) {
				send_post_request();
				return;
			}

			if( !exception_present ) {
				std::string result_hash{ calculate_md5( response_.body() ) };
				// if not false positive, we process the signature, otherwise, there's no point
				bool result_processed = display_result( current_url_, result_hash, status_code, path_, out_file_ );
				if( result_processed ) process_result_signature( response_.body() );
			}
		}
		disconnect();
	}

	void https_socket::resend_https_request()
	{
		++send_count_;
		if( send_count_ >= args_.max_send_count ) {
			server_error();
			disconnect();
		} else {
			send_https_data();
		}
	}
}

