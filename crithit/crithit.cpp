#include <chrono>
#include <string>
#include <fstream>
#include <thread>
#include <memory>
#include <boost/beast.hpp>
#include <boost/asio.hpp>
#include <tclap/CmdLine.h>
#include "request.hpp"

#ifdef _MSC_VER
#pragma warning(disable : 4996)
#endif

namespace tc = TCLAP;

namespace crithit
{
	void get_directory( command_line_args const & args, runtime_list_information const& runtime_info,
		safe_circular_index & proxy_indexer, threadsafe_vector<std::string>& fuzzer_list,
		std::shared_ptr<std::ostream> out_file )
	{
		auto& io_service{ GetIOService() };
		// insertion into a std::list is fast and it is guarantteed not to reallocate and move elements around
		std::list<std::unique_ptr<custom_http_socket>> socket_list{};
		std::size_t const socket_count{ minimum( args.max_sockets / args.thread_count, fuzzer_list.get_total() ) };
		for( std::size_t i = 0; i != socket_count; ++i ) {
			socket_list.emplace_back( std::make_unique<custom_http_socket>( io_service, args, runtime_info,
				proxy_indexer, fuzzer_list ) );
			socket_list.back()->set_output_file( out_file );
			socket_list.back()->start();
		}
		io_service.run();
	}

	void find_directories( command_line_args const & args, runtime_list_information const & runtime_info,
		threadsafe_vector<std::string>& fuzzer_list )
	{
		boost::asio::thread_pool tpool{ args.thread_count };
		if( args.verbose ) spdlog::info( "[+] Launching {} worker threads", args.thread_count );

		safe_circular_index proxy_indexer{ runtime_info.proxies.size() };
		std::shared_ptr<std::ostream> out_file{};

		if( args.output_filename == "stdout" ) {
			out_file = std::make_shared<std::ostream>( std::cout.rdbuf() );
		} else {
			out_file.reset( new std::ofstream( args.output_filename ) );
		}
		if( args.verbose ) spdlog::info( "Search started" );
		for( std::size_t i = 0; i != args.thread_count; ++i ) {
			boost::asio::post( tpool, std::bind( get_directory, std::cref( args ), std::cref( runtime_info ),
				std::ref( proxy_indexer ), std::ref( fuzzer_list ), out_file ) );
		}

		std::chrono::time_point<std::chrono::system_clock> start, end;
		start = std::chrono::system_clock::now();
		tpool.join();
		end = std::chrono::system_clock::now();

		std::chrono::duration<double> elapsed_seconds = end - start;
		auto const seconds = elapsed_seconds.count();
		int minutes = seconds / 60, hours = minutes / 60;
		if( runtime_info.is_using_signature ) output_signature( args.output_sig_file );
		if( args.verbose ) {
			spdlog::info( "[+] Elapsed {}hr: {}min: {}sec(s)", hours, minutes % 60,
				( std::size_t )seconds % 60 );
		}
	}

	void run_bruteforcer( command_line_args const & args )
	{
		issue_diagnostics_where_necessary( args );
		runtime_list_information runtime_info{};
		runtime_info.is_using_signature = !args.signature_file.empty();

		if( !args.exception_filename.empty() ) {
			smart_pointer<FILE, file_closer> exception_file{ fopen( args.exception_filename.c_str(), "w" ) };
			if( !exception_file ) {
				spdlog::error( "[-] Unable to open exception file `{}`", args.output_filename );
				return;
			}
			runtime_info.exception_list = get_list( exception_file );
		}
		if( !args.proxy_filename.empty() ) {
			smart_pointer<FILE, file_closer> proxy_file{ fopen( args.proxy_filename.c_str(), "r" ) };
			if( !proxy_file ) {
				spdlog::error( "[-] Unable to open proxy file" );
				return;
			}
			runtime_info.proxies = get_list( proxy_file );
		}
		if( runtime_info.is_using_signature ) {
			smart_pointer<FILE, file_closer> signature_file{ fopen( args.signature_file.c_str(), "r" ) };
			if( !signature_file ) {
				spdlog::error( "Unable to open file for signature lists" );
				return;
			}
			runtime_info.signatures = parse_signature_file( args.signature_file );
			if( runtime_info.signatures.string_search.empty() && runtime_info.signatures.regex_search.empty() ) {
				return;
			}
		}

		if( args.target.empty() ) {
			smart_pointer<FILE, file_closer> target_list_file{ fopen( args.target_filename.c_str(), "r" ) };
			if( !target_list_file ) {
				spdlog::error( "[-] Unable to open the target list" );
				return;
			}
			runtime_info.targets = get_list( target_list_file );
		} else {
			runtime_info.targets.push_back( args.target );
		}

		{
			smart_pointer<FILE, file_closer> word_list_file{ fopen( args.wordlist_filename.c_str(), "r" ) };
			if( !word_list_file ) {
				spdlog::error( "[-] Unable to open filename containing the word list" );
				return;
			}
			runtime_info.word_list = get_list( word_list_file );
		}

		threadsafe_vector<std::string> fuzzer_list{ 
			generate_fuzzer_list( runtime_info.targets, runtime_info.word_list, runtime_info.is_using_signature ) 
		};
		
		runtime_info.targets.clear(); runtime_info.targets.shrink_to_fit();
		runtime_info.word_list.clear(); runtime_info.word_list.shrink_to_fit();

		if( args.verbose ) spdlog::info( "Generated {} names to use", fuzzer_list.get_total() );
		request_handler::InitializeStatuses( args );
		find_directories( args, runtime_info, fuzzer_list );
	}
}

using namespace fmt::literals;

int main( int argc, char**argv )
{
	tc::CmdLine cmd_line{ "crithit by @codingo_ - directory bruteforing at scale", ' ', "0.2" };
	uint8_t const max_connect_interval = 5, max_read_interval = max_connect_interval * 2;

	unsigned short const thread_count = std::thread::hardware_concurrency();
	tc::ValueArg<std::string> wordlist_arg{ "w", "word-list", "a filename containing list of words to use",
		true, "", "filename" };
	tc::ValueArg<std::string> proxy_arg{ "p", "proxy", "a filename containing list of proxy names and port(IP:port)",
		false, "", "filename" };
	tc::ValueArg<std::string> target_arg{ "T", "target", "the target", false, "", "domain name" };
	tc::ValueArg<std::string> target_list_arg{ "t", "target-list", "a filename containing the list of targets", false,
		"", "filename" };
	tc::ValueArg<unsigned short> thread_count_arg{ "c", "threads", "Number of threads to use(default: {})"_format( thread_count ),
		false, thread_count, "integer" };
	tc::ValueArg<unsigned int> write_time_arg{ "n", "wait-for", "wait N seconds to connect/send data "
		"to server(default: {}secs)"_format( max_connect_interval ), false, max_connect_interval, "integer" };
	tc::ValueArg<unsigned int> read_time_arg{ "", "read-for", "wait N seconds to receive data from server"
		"(default: {}secs)"_format( max_read_interval ), false, max_read_interval, "integer" };
	tc::ValueArg<int> verify_results_arg{ "V", "verify", "verify successful results with different proxies", false, 1, "integer" };
	tc::ValueArg<std::string> output_arg{ "o", "output", "output result to (default: stdout)", false, "stdout", "filename" };
	tc::ValueArg<unsigned short> max_sockets_arg{ "", "max-sockets", "Number of sockets to use", false, 1'000, "integer" };
	tc::ValueArg<std::string> exception_list_arg{ "e", "exceptions", "filename containing words...", false, "", "filename" };
	tc::ValueArg<std::string> status_exceptions_arg{ "b", "statuscodesblacklist",
		"Negative status codes (will override statuscodes if set)", false, "400,404", "string" };
	tc::ValueArg<std::string> approved_status_arg{ "s", "statuscodes", "Positive status codes "
		"(will be overwritten with statuscodesblacklist if set)(default 200,204,301,302,307,401,403,408)", false,
		"200,204,301,302,307,401,403,408", "string" };
	tc::ValueArg<std::string> signature_arg{ "", "signatures", "file containing list of signatures to look out for "
		"in top-level domains", false, "", "filename" };
	tc::ValueArg<std::string> output_signature_arg{ "", "os", "if --signatures is specified, this specifies the output "
		"file to write result to", false, "", "filename" };

	tc::SwitchArg randomize_user_agent_arg{ "r", "randomize-agent", "use random user agents for requests", true };
	tc::SwitchArg result_verbose_arg{ "", "verbose", "be verbose with output", false };

	cmd_line.add( output_arg );
	cmd_line.add( wordlist_arg );
	cmd_line.add( result_verbose_arg );
	cmd_line.add( target_arg );
	cmd_line.add( target_list_arg );
	cmd_line.add( thread_count_arg );
	cmd_line.add( approved_status_arg );
	cmd_line.add( status_exceptions_arg );
	cmd_line.add( randomize_user_agent_arg );
	cmd_line.add( verify_results_arg );
	cmd_line.add( max_sockets_arg );
	cmd_line.add( proxy_arg );
	cmd_line.add( read_time_arg );
	cmd_line.add( write_time_arg );
	cmd_line.add( exception_list_arg );
	cmd_line.add( signature_arg );
	cmd_line.add( output_signature_arg );

	try {
		cmd_line.parse( argc, argv );
	} catch( std::exception & e ) {
		spdlog::error( e.what() );
		return -1;
	}

	crithit::command_line_args args{};
	args.verify_count = verify_results_arg.getValue();
	args.randomize_user_agent = randomize_user_agent_arg.getValue();
	args.output_filename = output_arg.getValue();
	args.thread_count = thread_count_arg.getValue();
	args.wordlist_filename = wordlist_arg.getValue();
	args.max_sockets = max_sockets_arg.getValue();
	args.verbose = result_verbose_arg.getValue();
	args.target = target_arg.getValue();
	args.target_filename = target_list_arg.getValue();
	args.proxy_filename = proxy_arg.getValue();
	args.max_timeout_milli = write_time_arg.getValue() * 1'000;
	args.max_receiving_timeout = read_time_arg.getValue() * 1'000;
	args.exception_filename = exception_list_arg.getValue();
	args.status_accepted = approved_status_arg.getValue();
	args.status_exempted = status_exceptions_arg.getValue();
	args.signature_file = signature_arg.getValue();
	args.output_sig_file = output_signature_arg.getValue();

	if( args.verbose ) crithit::print_banner();
	crithit::run_bruteforcer( args );

	return 0;
}
