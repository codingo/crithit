#pragma once

#include <memory>
#include <vector>
#include <list>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/asio.hpp>
#include "utils.hpp"

using StringList = std::vector<std::string>;

namespace beast = boost::beast;
namespace net = boost::asio;
namespace http = beast::http;
namespace ssl = boost::asio::ssl; 
using tcp = boost::asio::ip::tcp;

namespace crithit
{
	class custom_http_socket;
	ssl::context create_ssl_context();

	class https_socket
	{
		net::io_context &io_;
		ssl::context ctx_;
		beast::ssl_stream<beast::tcp_stream> tcp_stream_;
		tcp::resolver resolver_;
		beast::flat_buffer buffer_;
		http::request<http::string_body> get_request_;
		http::request<http::string_body> post_request_;
		http::response<http::string_body> response_;
		tcp::resolver::results_type result_;
		std::shared_ptr<std::ostream> out_file_;
		command_line_args const & args_;
		runtime_list_information const & runtime_info_;
		std::list<std::unique_ptr<https_socket>>::iterator iter_;
		custom_http_socket* parent_;
		std::string current_url_{};
		std::string host_{};
		std::string path_{};
		unsigned int connect_count_{};
		unsigned int send_count_{};
		unsigned int handshake_count_{};
		unsigned int post_data_size{};
		
		bool is_post_request = false;
		bool report_408 = false;
	private:
		void create_request_data( std::string const & method );
		void perform_handshake();
		void on_handshook( beast::error_code ec );
		void on_host_resolved( beast::error_code, tcp::resolver::results_type );
		void connect();
		void on_connected( beast::error_code, tcp::resolver::results_type::endpoint_type );
		void process_result_signature( std::string const & response_body );
		void send_https_data();
		void on_data_sent( beast::error_code, std::size_t const );

		void receive_data();
		void on_data_received( beast::error_code, std::size_t const );

		void disconnect();
		void reconnect();
		void resend_https_request();
		void process_proxy( std::string const &port = "https" );
		void send_post_request();
		void server_error();
	public:
		https_socket( net::io_context& io, command_line_args const & args, 
			runtime_list_information const & runtime_info );
		~https_socket();
		void set_output_file( std::shared_ptr<std::ostream> o );
		void start_connect( std::string && url );
		void set_remove_iterator( custom_http_socket* parent, std::list<std::unique_ptr<https_socket>>::iterator iter );
	};
}
