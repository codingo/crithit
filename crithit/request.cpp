#include "request.hpp"
#include <vector>
#include <map>
#include "utils.hpp"
#include "https_socket.hpp"

namespace crithit
{
	using namespace fmt::literals;

	beast::net::io_context& GetIOService()
	{
		static beast::net::io_context context{};
		return context;
	}

	void custom_http_socket::server_error()
	{
		if( report_408 ) display_result( current_url_, "", 408, path_, out_file_ );
		next_request();
	}

	void custom_http_socket::process_result_signature( std::string const& response_body )
	{
		if( runtime_info_.is_using_signature ) {
			process_string_signature( runtime_info_.signatures.string_search, response_body, current_url_ );
			process_regex_signature( runtime_info_.signatures.regex_search, response_body, current_url_ );
		}
	}

	void custom_http_socket::send_http_data()
	{
		tcp_stream_.expires_after( std::chrono::milliseconds( args_.max_timeout_milli ) );
		if( is_post_request ) {
			http::async_write( tcp_stream_, post_request_, beast::bind_front_handler( &custom_http_socket::on_data_sent,
				this ) );
		} else {
			http::async_write( tcp_stream_, get_request_, beast::bind_front_handler( &custom_http_socket::on_data_sent,
				this ) );
		}
	}

	void custom_http_socket::on_data_sent( beast::error_code ec, std::size_t const )
	{
		if( ec ) {
#ifdef DEBUG
			spdlog::info( "Sending error `{}` for `{}`", ec.message(), current_url_ );
#endif // DEBUG
			resend();
		} else receive_data();
	}

	void custom_http_socket::resend()
	{
		++send_count_;
		if( send_count_ >= args_.max_send_count ) server_error();
		else send_http_data();
	}

	void custom_http_socket::on_redirect( std::string address )
	{
		if( is_https( address ) ) {
			auto new_https_connection = std::make_unique<https_socket>( io_, args_, runtime_info_ );
			auto iter = secure_sockets.insert( secure_sockets.end(), std::move( new_https_connection ) );
			secure_sockets.back()->set_output_file( out_file_ );
			secure_sockets.back()->set_remove_iterator( this, iter );
			secure_sockets.back()->start_connect( std::move( address ) );
			next_request();
		} else {
			current_url_ = std::move( address );
			process_request( "http" );
		}
	}

	void custom_http_socket::remove_https_connection( std::list<std::unique_ptr<https_socket>>::iterator iter )
	{
		secure_sockets.erase( iter );
	}

	void custom_http_socket::set_output_file( std::shared_ptr<std::ostream> outfile )
	{
		out_file_ = outfile;
	}

	void custom_http_socket::receive_data()
	{
		// receiving usually take time, so let's double the wait time for receiving
		tcp_stream_.expires_after( std::chrono::milliseconds( args_.max_receiving_timeout ) );
		http::async_read( tcp_stream_, buffer_, response_,
			beast::bind_front_handler( &custom_http_socket::on_data_received, this ) );
	}

	void custom_http_socket::on_data_received( beast::error_code ec, std::size_t const bytes_received )
	{
		if( ec ) {
#ifdef DEBUG
			spdlog::info( "Received error: `{}` for `{}`", ec.message(), current_url_ );
#endif // DEBUG
			if( report_408 ) display_result( current_url_, "", 408, path_, out_file_ );
			next_request();
			return;
		}

		int const status_code = response_.result_int();
		if( status_found_in( status_code, request_handler::exempted_statuses ) ) {
#ifdef DEBUG
			spdlog::info( "status code `{}` found exempted for `{}`", status_code, current_url_ );
#endif // DEBUG
			next_request();
			return;
		} else if( status_found_in( status_code, request_handler::accepted_statuses ) ) {
			if( status_found_in( status_code, { 300, 301, 302, 307, 308 } ) ) { // handle redirect
				std::string new_url{ response_[beast::http::field::location].to_string() };
				if( new_url.front() == '/' ) {
					new_url = "{}{}"_format( host_, new_url );
				}
				on_redirect( std::move( new_url ));
				return;
			}
			if( !is_post_request && status_code == 200 ) {
#ifdef DEBUG
				spdlog::info( "GET request got 200 for `{}`, sending POST request", current_url_ );
#endif // DEBUG
				send_post_request();
				return;
			}
			bool const exception_present = in_exception_list( runtime_info_.exception_list, response_.body() );
			if( !exception_present ) {
				std::string result_hash{ calculate_md5( response_.body() ) };
				// if not false positive, we process the signature, otherwise, there's no point
				bool result_processed = display_result( current_url_, result_hash, status_code, path_, out_file_ );
#ifdef DEBUG
				if( !result_processed ) spdlog::info( "Hash `{}` not processed" );
#endif // DEBUG
				if( result_processed ) process_result_signature( response_.body() );
			}
		}
		next_request();
	}

	void custom_http_socket::send_post_request()
	{
		is_post_request = true;
		post_data_size = 0;
		create_request_data( "POST" );
		send_http_data();
	}

	void custom_http_socket::reconnect()
	{
		++connect_count_;
		if( connect_count_ >= args_.max_reconnect ) {
#ifdef DEBUG
			spdlog::info( "Giving up on `{}` after {} reconnects", current_url_, connect_count_ );
#endif // DEBUG
			server_error();
		} else resolve_host();
	}

	void custom_http_socket::on_host_resolved( beast::error_code ec, tcp::resolver::results_type result )
	{
		if( ec ) {
#ifdef DEBUG
			spdlog::info( "Resolve error `{}` for `{}`", ec.message(), host_ );
#endif // DEBUG
			server_error();
		} else connect( result );
	}

	void custom_http_socket::connect( tcp::resolver::results_type result )
	{
		tcp_stream_.expires_after( std::chrono::milliseconds( args_.max_timeout_milli ) );
		tcp_stream_.async_connect( result, beast::bind_front_handler( &custom_http_socket::on_connected, this ) );
	}

	void custom_http_socket::on_connected( beast::error_code ec, tcp::resolver::results_type::endpoint_type )
	{
		if( ec ) {
#ifdef DEBUG
			spdlog::info( "Connect error `{}` for `{}`", ec.message(), host_ );
#endif // DEBUG
			reconnect();
		} else send_http_data();
	}

	void custom_http_socket::resolve_host( std::string const& port )
	{
		resolver_.async_resolve( host_, port,
			beast::bind_front_handler( &custom_http_socket::on_host_resolved, this ) );
	}

	void custom_http_socket::process_request( std::string const& port )
	{
		is_post_request = false;
		post_data_size = 0;
		uri u{ current_url_ };
		host_ = u.host();
		path_ = u.path();

		create_request_data( "GET" );
		resolve_host();
	}

	void custom_http_socket::next_request()
	{
		try {
			current_url_ = fuzzer_list_.get();
			connect_count_ = send_count_ = 0;
			process_request( "80" );
		} catch( empty_container_exception const& ) {
		}
	}

	void custom_http_socket::create_request_data( std::string const& method )
	{
		if( method == "GET" ) {
			get_request_.method( beast::http::verb::get );
			get_request_.version( 11 );

			if( runtime_info_.proxies.empty() ) get_request_.target( path_ );
			else get_request_.target( current_url_ );

			get_request_.set( beast::http::field::host, host_ );
			get_request_.set( beast::http::field::accept, "*/*" );
			get_request_.set( beast::http::field::connection, "keep-alive" );
			get_request_.set( beast::http::field::cache_control, "no-cache" );
			get_request_.set( beast::http::field::user_agent, get_random_agent() );
		} else {
			post_request_.method( beast::http::verb::post );
			post_request_.version( 11 );

			if( runtime_info_.proxies.empty() ) post_request_.target( path_ );
			else post_request_.target( current_url_ );

			post_request_.set( beast::http::field::host, host_ );
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

	custom_http_socket::custom_http_socket( net::io_context& io_context, command_line_args const& args,
		runtime_list_information const& runtime_info, safe_circular_index& proxy_indexer,
		threadsafe_vector<std::string>& fuzzer_list ) : io_{ io_context }, args_{ args },
		runtime_info_{ runtime_info }, proxy_index_{ proxy_indexer }, fuzzer_list_{ fuzzer_list },
		resolver_{ net::make_strand( io_ ) }, tcp_stream_{ net::make_strand( io_ ) },
		report_408{ status_found_in( 408, request_handler::accepted_statuses ) &&
			!status_found_in( 408, request_handler::exempted_statuses ) }
	{
	}

	void custom_http_socket::start()
	{
		next_request();
	}

	void https_socket::disconnect()
	{
		tcp_stream_.async_shutdown( [=]( beast::error_code ) {
			parent_->remove_https_connection( iter_ );
		} );
	}
}