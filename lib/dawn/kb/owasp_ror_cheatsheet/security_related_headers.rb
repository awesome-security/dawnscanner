module Dawn
  module Kb
    module OwaspRorCheatSheet
      class SecurityRelatedHeadersA
        include PatternMatchCheck

        def initialize
          super({
            :name=>"Owasp Ror CheatSheet: Security Related Headers",
            :kind=>Dawn::KnowledgeBase::PATTERN_MATCH_CHECK,
            :applies=>["rails"],
            :glob=>"**/controllers/*.rb",
            :aux_links=>["https://www.owasp.org/index.php/Ruby_on_Rails_Cheatsheet"],
            :message=>message,
            :attack_pattern => [
              "response.headers\\['X-Frame-Options'\\] = 'DENY'",
              "response.headers\\['X-Content-Type-Options'\\] = 'nosniff'",
              "response.headers\\['X-XSS-Protection'\\] = '1'",
              "ActionDispatch::Response.default_headers = {
                  'X-Frame-Options' => 'DENY',
                  'X-Content-Type-Options' => 'nosniff',
                  'X-XSS-Protection' => '1;'
                }",
              "SecureHeaders::Configuration.default do |config|
                  config.x_frame_options = 'DENY'
                  config.x_content_type_options = 'nosniff'
                  config.x_xss_protection = '1; mode=block'
                end"
            ],
            :negative_search=>true,
            :check_family=>:owasp_ror_cheatsheet,
            :severity=>:info,
          })
        end
      end

      class SecurityRelatedHeadersB
        include DependencyCheck

        def initialize
          super({
            :name=>"SecurityRelatedHeadersB",
            :cvss=>"",
            :release_date => Date.new(2016, 9, 27),
            :cwe=>"",
            :owasp=>"",
            :applies=>["rails"],
            :kind=>Dawn::KnowledgeBase::DEPENDENCY_CHECK,
          })

          self.safe_dependencies = [{:name=>"secure_header", :version=>['99.99.99']}]

        end
      end
      class SecurityRelatedHeaders
        include ComboCheck

        message = "To set a header value, simply access the response.headers object as a hash inside your controller (often in a before/after_filter). Rails 4 provides the \"default_headers\" functionality that will automatically apply the values supplied. This works for most headers in almost all cases."
        def initialize

          super({
            :name=>"Owasp Ror CheatSheet: Security Related Headers",
            :applies=>["rails"],
            :kind=>Dawn::KnowledgeBase::COMBO_CHECK,
            :message=>message,
            :mitigation=>"Use response headers like X-Frame-Options, X-Content-Type-Options, X-XSS-Protection in your project.",
            :checks=>[SecurityRelatedHeadersA.new, SecurityRelatedHeadersB.new]
          })

        end
      end

    end
  end
end
