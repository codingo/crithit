#include "utils.hpp"
#include <algorithm>
#include <array>
#include <map>
#include <set>
#include <cctype>
#include <random>
#include <fstream>
#include <regex>
#include <boost/algorithm/string.hpp>
#include <openssl/md5.h> //used for hashing
#include <spdlog/spdlog.h>

#ifdef _MSC_VER
#pragma warning(disable : 4996)
#endif

namespace crithit
{
	using namespace fmt::v5::literals;

	std::array<char const*, LEN_USER_AGENTS> request_handler::user_agents = {
		"Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2226.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1",
		"Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.0",
		"Mozilla/5.0 (X11; Linux i586; rv:31.0) Gecko/20100101 Firefox/31.0",
		"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:31.0) Gecko/20130401 Firefox/31.0",
		"Mozilla/5.0 (Windows NT 5.1; rv:31.0) Gecko/20100101 Firefox/31.0",
		"Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko",
		"Mozilla/5.0 (Windows; U; MSIE 9.0; WIndows NT 9.0; en-US))",
		"Mozilla/5.0 (Windows; U; MSIE 9.0; Windows NT 9.0; en-US)",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:68.0) Gecko/20100101 Firefox/68.0",
		"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:67.0) Gecko/20100101 Firefox/67.0",
		"Mozilla/5.0 (X11; Linux i686; rv:67.0) Gecko/20100101 Firefox/67.0",
		"Mozilla/5.0 (X11; Linux x86_64; rv:67.0) Gecko/20100101 Firefox/67.0",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.28 Safari/537.36 OPR/61.0.3298.6 (Edition developer)",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.140 Safari/537.36 Edge/17.17134",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.134 Safari/537.36 Vivaldi/2.5.1525.40"
	};
	IntegerList request_handler::accepted_statuses{};
	IntegerList request_handler::exempted_statuses{};
	StringList request_handler::alert_descriptors{};
	std::vector<SignatureSearchResult> request_handler::signature_search_results{};

	bool is_https( std::string const& url )
	{
		return boost::starts_with( url, "https://" );
	}

	bool display_result( std::string const& url, std::string const& hash, int const status_code,
		std::string const& path, std::shared_ptr<std::ostream> out )
	{
		static std::set<std::string> hashes{};
		if( !hash.empty() ) {
			if( hashes.find( hash ) != hashes.cend() ) return false; // false positive
			std::lock_guard<std::mutex> lock_g{ global_output_mutex };
			hashes.insert( hash );
		}
		std::lock_guard<std::mutex> lock_g{ global_output_mutex };
		( *out ) << url << ", " << ( path.empty() ? "/" : path.c_str() + 1 ) << ", " << status_code << "\n" << std::flush;
		return true;
	}

	StringList get_list( smart_pointer<FILE, file_closer>& file )
	{
		char buffer[0x200]{};
		std::set<std::string> list{};
		while( fgets( buffer, sizeof( buffer ), file ) ) {
			trim_end( buffer );
			char const* address = trim_start( buffer );
			if( strlen( address ) == 0 ) continue;
			list.insert( address );
		}
		return StringList( list.begin(), list.end() );
	}

	char* trim_start( char* str )
	{
		while( 0 != *str ) {
			if( !isspace( *str ) ) {
				return str;
			}
			str++;
		}
		return str;
	}

	void trim_end( char* str )
	{
		char* last = str + strlen( str ) - 1;
		while( last >= str ) {
			if( !isspace( *last ) ) {
				return;
			}
			*last = 0;
			last--;
		}
	}

	std::string calculate_md5( std::string const& str )
	{
		MD5_CTX md5{};
		MD5_Init( &md5 );
		MD5_Update( &md5, (unsigned char const*) str.c_str(), str.size() );
		unsigned char hash[16]{};
		MD5_Final( hash, &md5 );

		std::string result{};
		result.reserve( 32 );

		for( std::size_t i = 0; i != 16; ++i ) {
			result += ( "0123456789ABCDEF"[hash[i] / 16] );
			result += ( "0123456789ABCDEF"[hash[i] % 16] );
		}

		return result;
	}

	IntegerList split_status( std::string const& status_codes )
	{
		StringList string_split{};
		IntegerList final_result{};
		boost::split( string_split, status_codes, [=]( char const ch ) { return ch == ','; } );
		std::transform( string_split.cbegin(), string_split.cend(), std::back_inserter( final_result ),
			[]( std::string const& a ) { return std::stoi( a ); } );
		return final_result;
	}

	bool status_found_in( int const status_code, IntegerList const& container )
	{
		for( int i = 0; i != container.size(); ++i ) {
			if( container[i] == status_code ) return true;
		}
		return false;
	}

	StringList generate_fuzzer_list( StringList const& targets, StringList const& word_list, bool using_signature )
	{
		std::size_t const reserved_space = ( targets.size() * word_list.size() ) +
			( using_signature ? targets.size() : 0 );
		StringList result{};
		result.reserve( reserved_space );
		for( auto& w : word_list ) {
			char const* word = w.front() == '/' ? w.c_str() + 1 : w.c_str();
			for( auto const& target : targets ) {
				if( target.back() == '/' ) result.emplace_back( target + word );
				else result.emplace_back( target + "/" + word );
			}
		}
		if( using_signature ) result.insert( result.end(), targets.cbegin(), targets.cend() );
		return result;
	}

	bool in_exception_list( StringList const& exception_list, std::string const& result_body )
	{
		if( exception_list.empty() ) return false;

		aho_corasick::trie word_trie{};
		word_trie.case_insensitive();
		word_trie.insert( exception_list.cbegin(), exception_list.cend() );
		auto search_result = word_trie.parse_text( result_body );
		return !search_result.empty();
	}

	std::string get_random_agent()
	{
		static std::random_device rd{};
		static std::mt19937  gen{ rd() };
		static std::uniform_int_distribution<> uid( 0, 17 );
		return request_handler::user_agents[uid( gen )];
	}

	std::string get_next_proxy( StringList const& proxy_list, safe_circular_index& indexer )
	{
		return proxy_list[indexer.get_index()];
	}

	uri::uri( const std::string& url_s )
	{
		parse( url_s );
	}

	std::string uri::path() const
	{
		return path_;
	}

	std::string uri::host() const
	{
		return host_;
	}

	void uri::parse( const std::string& url_s )
	{
		std::string const prot_end{ "://" };
		std::string::const_iterator prot_i = std::search( url_s.begin(), url_s.end(),
			prot_end.begin(), prot_end.end() );
		protocol_.reserve( distance( url_s.begin(), prot_i ) );
		std::transform( url_s.begin(), prot_i,
			std::back_inserter( protocol_ ), []( int c ) { return std::tolower( c ); } );
		if( prot_i == url_s.end() ) {
			prot_i = url_s.begin();
		} else {
			std::advance( prot_i, prot_end.length() );
		}
		std::string::const_iterator path_i = std::find( prot_i, url_s.end(), '/' );
		host_.reserve( distance( prot_i, path_i ) );
		std::transform( prot_i, path_i,
			std::back_inserter( host_ ), []( int c ) { return std::tolower( c ); } );
		std::string::const_iterator query_i = find( path_i, url_s.end(), '?' );
		path_.assign( path_i, query_i );
		if( query_i != url_s.end() )
			++query_i;
		query_.assign( query_i, url_s.end() );
	}

	void print_banner()
	{
		// courtesy of http://www.patorjk.com/software/taag/#p=display&f=Epic&t=CritHit
		std::string header = R"sep(
 _______  _______ __________________         __________________
(  ____ \(  ____ )\__   __/\__   __/|\     /|\__   __/\__   __/
| (    \/| (    )|   ) (      ) (   | )   ( |   ) (      ) (   
| |      | (____)|   | |      | |   | (___) |   | |      | |   
| |      |     __)   | |      | |   |  ___  |   | |      | |   
| |      | (\ (      | |      | |   | (   ) |   | |      | |   
| (____/\| ) \ \_____) (___   | |   | )   ( |___) (___   | |   
(_______/|/   \__/\_______/   )_(   |/     \|\_______/   )_(   
)sep";
		std::printf( "%s", header.c_str() );
	}

	auto ascii_random_choice() -> char
	{
		static std::random_device rd{};
		static std::mt19937  generator{ rd() };
		static std::uniform_int_distribution<> ui_distr( 0, 52 );
		return "abcdefghijklmnopqrstuvwxyz_ABCDEFGHIJKLMNOPQRSTUVWXYZ"[ui_distr( generator )];
	}

	auto random_string( int const length ) -> std::string
	{
		std::string str( length, 0 );
		for( int i = 0; i != length; ++i ) str[i] = ascii_random_choice();
		return str;
	}

	void request_handler::InitializeStatuses( command_line_args const& args )
	{
		accepted_statuses = split_status( args.status_accepted );
		exempted_statuses = split_status( args.status_exempted );
	}

	void issue_diagnostics_where_necessary( command_line_args const& args )
	{
		bool const checking_signature{ !args.signature_file.empty() },
			output_sig_specified{ !args.output_sig_file.empty() };
		if( ( checking_signature && !output_sig_specified ) || ( output_sig_specified && !checking_signature ) ) {
			spdlog::warn( "One of the signature options is missing, this may cause irregularities" );
			std::exit( -1 );
		}
		if( checking_signature ) {
			smart_pointer<FILE, file_closer> output_sig_file{ fopen( args.output_sig_file.c_str(), "w" ) };
			if( !output_sig_file ) {
				spdlog::error( "Unable to open output file for signature result" );
				std::exit( -1 );
			}
		}

		if( args.output_filename != "stdout" ) {
			smart_pointer<FILE, file_closer> out_file{ fopen( args.output_filename.c_str(), "w" ) };
			if( !out_file ) {
				spdlog::error( "[-] Unable to open `{}` for write.", args.output_filename );
				std::exit( -1 );
			}
		}
		if( args.target.empty() && args.target_filename.empty() ) {
			spdlog::error( "[-] You need to specify a target(-T) or a target list(-t)" );
			std::exit( -1 );
		}

		if( args.output_filename == args.wordlist_filename || args.wordlist_filename == args.output_sig_file ) {
			spdlog::warn( "Some I/O files points to the file, you may want to check before moving forward" );
			std::exit( -1 );
		}
	}

	void process_string_signature( std::vector<Signature::SignatureItem> const& signature,
		std::string const& response_body, std::string const& url )
	{
		if( signature.empty() || response_body.empty() ) return;

		aho_corasick::trie word_trie{};
		word_trie.case_insensitive();
		for( auto const& item : signature ) {
			word_trie.insert( item.str );
		}
		auto search_result = word_trie.parse_text( response_body );

		for( auto const& item : search_result ) {
			std::string const key = item.get_keyword();
			auto iter = std::find_if( signature.cbegin(), signature.cend(), [&]( auto const& sig_item ) {
				return boost::iequals( sig_item.str, key );
			} );
			if( iter == signature.cend() ) continue;
			std::string& alert_desc = request_handler::alert_descriptors[iter->alert_index];
			{
				std::lock_guard<std::mutex> lock_g{ global_signature_mutex };
				request_handler::signature_search_results.emplace_back( 
					SignatureSearchResult{ "string_search", key, url, alert_desc } );
			}
		}
	}

	// to-do: refine the search to show matches rather than the regex string that matched
	void process_regex_signature( std::vector<Signature::SignatureItem> const& signature,
		std::string const& response_body, std::string const& url )
	{
		std::smatch base_match{};
		for( auto const& sig : signature ) {
			std::regex rg_object{ sig.str, std::regex_constants::ECMAScript };
			if( std::regex_match( response_body, base_match, rg_object ) ) {
				std::string alert_desc = request_handler::alert_descriptors[sig.alert_index];
				{
					std::lock_guard<std::mutex> lock_g{ global_signature_mutex };
					request_handler::signature_search_results.emplace_back(
						SignatureSearchResult{ "regex", base_match[0], url, alert_desc }
					);
				}
			}
		}
	}

	void to_json( json& j, SignatureSearchResult const& result )
	{
		j = json{ { "string", result.search_string }, { "found_in", result.url }, { "alert", result.alert },
		{"search_type", result.search_type} };
	}

	void output_signature( std::string const& filename )
	{
		json json_object{ request_handler::signature_search_results };
		{
			std::ofstream out_file{ filename };
			if( out_file ) {
				out_file << json_object.dump( 2 ) << std::endl;
				return;
			}
		}
		spdlog::warn( "Unable to open {} for use for signature output file", filename );
		std::string new_filename{ random_string( 10 ) + ".json" };
		std::ofstream out_file{ new_filename };

		if( !out_file ) {
			spdlog::error( "Unable to open a randomly generated name {} write too.", new_filename );
		} else {
			out_file << json_object.dump( 2 ) << std::endl;
		}
	}

	auto parse_signature_file( std::string const& filename ) -> Signature
	{
		json json_object{};
		try {
			{
				std::ifstream in_file{ filename };
				in_file >> json_object;
			}

			json::array_t root_element = json_object.get<json::array_t>();
			Signature signature{};

			for( std::size_t i = 0; i != root_element.size(); ++i ) {
				json::object_t item = root_element[i].get<json::object_t>();
				std::vector<Signature::SignatureItem>& container{
					boost::iequals( item.at( "type" ).get<json::string_t>(), "regex" ) ?
					signature.regex_search : signature.string_search
				};
				std::string	alert_desc{ item.at( "alertDescription" ).get<json::string_t>() };
				request_handler::alert_descriptors.emplace_back( std::move( alert_desc ) );
				std::size_t const descriptor_index = request_handler::alert_descriptors.size() - 1;

				json::array_t sigs{ item.at( "signatures" ).get<json::array_t>() };
				for( std::size_t index = 0; index != sigs.size(); ++index ) {
					container.emplace_back( Signature::SignatureItem{
						boost::algorithm::to_lower_copy( sigs[index].get<json::string_t>() ),
						descriptor_index } );
				}
			}
			return signature;
		} catch( std::exception const& e ) {
			spdlog::critical( "[x] Unable to read data from file: {}", e.what() );
			return {};
		}
	}
}
