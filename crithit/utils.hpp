#pragma once

#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <aho_corasick.hpp>
#include <nlohmann_json.hpp>

#define LEN_USER_AGENTS 18

static std::mutex global_output_mutex{};
static std::mutex global_signature_mutex{};

namespace crithit
{
	using StringList = std::vector<std::string>;
	using IntegerList = std::vector<int>;
	using json = nlohmann::json;

	struct command_line_args;
	
	struct SignatureSearchResult
	{
		std::string search_type;
		std::string search_string;
		std::string url;
		std::string alert;
	};

	struct request_handler
	{
		static std::array<char const*, LEN_USER_AGENTS> user_agents;
		static IntegerList accepted_statuses;
		static IntegerList exempted_statuses;
		static StringList alert_descriptors;
		static std::vector<SignatureSearchResult> signature_search_results;
		static void InitializeStatuses( command_line_args const & args );
	};

	struct uri
	{
		uri( const std::string& url_s );
		std::string host() const;
		std::string path() const;
	private:
		void parse( const std::string& url_s );
	private:
		std::string protocol_{};
		std::string host_{};
		std::string path_{};
		std::string query_{};
	};
	
	struct Signature
	{
		struct SignatureItem
		{
			std::string str{};
			std::size_t alert_index{};
		};
		std::vector<SignatureItem> string_search{};
		std::vector<SignatureItem> regex_search{};
	};

	struct runtime_list_information
	{
		StringList targets{};
		StringList proxies{};
		StringList word_list{};
		StringList exception_list{};
		Signature signatures{};

		bool is_using_signature{ false };
	};

	struct command_line_args
	{
		std::string target;
		std::string target_filename;
		std::string wordlist_filename;
		std::string output_filename;
		std::string proxy_filename;
		std::string exception_filename;
		std::string status_exempted{};
		std::string status_accepted{};
		std::string signature_file{};
		std::string output_sig_file{};

		unsigned short max_reconnect{ 5 };
		unsigned short max_redirect{ 5 };
		unsigned short max_send_count{ 5 };
		unsigned short thread_count{};
		unsigned short max_sockets{};
		unsigned short verify_count{};
		unsigned int   max_timeout_milli{ 5'000 };
		unsigned int   max_receiving_timeout{};
		bool		   randomize_user_agent{ true };
		bool           verbose{ false };
	};

	struct empty_container_exception : public std::runtime_error
	{
		empty_container_exception() : std::runtime_error("") {}
	};

	template<typename T>
	struct threadsafe_vector
	{
	private:
		std::mutex mutex_{};
		std::vector<T> container_;
		std::size_t const total_;
	public:
		threadsafe_vector( std::vector<T> && container ) : container_{ std::move( container ) },
			total_{ container_.size() }{
		}

		T get() {
			std::lock_guard<std::mutex> lock{ mutex_ };
			if( container_.empty() ) throw empty_container_exception{};
			T value = container_.back();
			container_.pop_back();
			return value;
		}
		std::size_t get_total() const
		{
			return total_;
		}
	};

	class safe_circular_index
	{
		std::mutex mutex_{};
		std::size_t const total_;
		unsigned int current_index_;
	public:
		safe_circular_index( std::size_t const total ) : total_{ total }, current_index_{ 0 }
		{
		}
		std::size_t get_index() {
			std::lock_guard<std::mutex> lock_g{ mutex_ };
			std::size_t temp = current_index_++;
			if( current_index_ == total_ ) current_index_ = 0;
			return temp;
		}
	};

	struct file_closer
	{
		void operator()( FILE *f ) const {
			if( f ) fclose( f );
		}
	};

	template<typename T, typename Deleter = std::default_delete<T>>
	class smart_pointer
	{
	private:
		T* data;
	public:
		smart_pointer() = default;
		smart_pointer( T * d ) : data( d ) {}
		smart_pointer( smart_pointer const & ) = delete;
		smart_pointer& operator=( smart_pointer const & ) = delete;
		void reset( T *p = nullptr ) {
			if( data ) Deleter{}( data );
			data = p;
		}
		operator bool() {
			return data;
		}
		operator T*() {
			return data;
		}
		~smart_pointer() {
			if( data ) Deleter{}( data );
		}
	};
	void print_banner();
	char *trim_start( char *str );
	void trim_end( char* str );

	StringList get_list( smart_pointer<FILE, file_closer> & file );
	StringList generate_fuzzer_list( StringList const & targets, StringList const & word_list, bool using_signature );
	bool in_exception_list( StringList const & exception_list, std::string const & result_body );
	std::string get_random_agent();
	std::string get_next_proxy( StringList const & proxy_list, safe_circular_index& indexer );
	char ascii_random_choice();
	std::string random_string( int const length );
	bool is_https( std::string const & url );
	bool display_result( std::string const & url, std::string const & hash, int const status_code, 
		std::string const & path, std::shared_ptr<std::ostream> );
	std::string calculate_md5( std::string const & str );
	IntegerList split_status( std::string const & status_codes );
	bool status_found_in( int const status_code, IntegerList const & container );
	void issue_diagnostics_where_necessary( command_line_args const & args );
	Signature parse_signature_file( std::string const & filename );
	void process_string_signature( std::vector<Signature::SignatureItem> const & signature, 
		std::string const & response_body, std::string const & url );
	void process_regex_signature( std::vector<Signature::SignatureItem> const & signature, 
		std::string const & response_body, std::string const & url );
	void output_signature( std::string const & filename );
	void to_json( json& j, SignatureSearchResult const& result );
	template<typename T, typename U>
	auto minimum( T first, U second )
	{
		return first < second ? first : second;
	}
}