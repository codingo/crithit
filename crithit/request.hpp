#pragma once

#include <chrono>
#include <string>
#include <list>
#include <atomic>
#include <spdlog/spdlog.h>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/asio/strand.hpp>
#include <aho_corasick.hpp>

#include "https_socket.hpp"

namespace beast = boost::beast;
namespace net = boost::asio;
namespace http = beast::http;
using tcp = boost::asio::ip::tcp;

namespace crithit
{
	beast::net::io_context& GetIOService();

	class custom_http_socket
	{
		friend class https_socket;
		net::io_context &io_;
		beast::tcp_stream tcp_stream_;
		tcp::resolver resolver_;
		beast::flat_buffer buffer_;
		http::request<http::empty_body> get_request_;
		http::request<http::string_body> post_request_;
		http::response<http::string_body> response_;
		
		std::list<std::unique_ptr<https_socket>> secure_sockets;

		command_line_args const & args_;
		runtime_list_information const & runtime_info_;
		threadsafe_vector<std::string>& fuzzer_list_;
		safe_circular_index& proxy_index_;
		std::shared_ptr<std::ostream> out_file_;
		std::string current_url_{}, host_{}, path_{};
		unsigned int connect_count_{};
		unsigned int send_count_{};
		unsigned int post_data_size{};
		
		bool is_post_request = false;
		bool report_408 = false;
	private:
		void create_request_data( std::string const & method );
		void process_result_signature( std::string const & response_body );
		void next_request();
		void process_request( std::string const & port );
		
		void on_host_resolved( beast::error_code, tcp::resolver::results_type );
		void connect( tcp::resolver::results_type );
		void on_connected( beast::error_code ec, tcp::resolver::results_type::endpoint_type );
		void send_http_data();
		void on_data_sent( beast::error_code, std::size_t const );
		
		void receive_data();
		void reconnect();
		void resend();
		void on_data_received( beast::error_code, std::size_t const );
		
		void resolve_host( std::string const &service = "http" );
		void send_post_request();
		void on_redirect( std::string address );
		void server_error();
	public:
		custom_http_socket( net::io_context& io_context_, command_line_args const & args,
			runtime_list_information const& runtime_info, safe_circular_index & proxy_indexer, 
			threadsafe_vector<std::string>& fuzzer_list );
		void start();
		void set_output_file( std::shared_ptr<std::ostream> outfile );
		void remove_https_connection( std::list<std::unique_ptr<https_socket>>::iterator iter );
	};
}
