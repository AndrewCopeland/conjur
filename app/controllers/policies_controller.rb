# frozen_string_literal: true

require 'multipart_parser/reader'

class PoliciesController < RestController
  include FindResource
  include AuthorizeResource
  
  before_filter :current_user
  before_filter :find_or_create_root_policy

  rescue_from Sequel::UniqueConstraintViolation, with: :concurrent_load

  def put
    authorize :update

    load_policy perform_automatic_deletion: true, delete_permitted: true, update_permitted: true
  end

  def patch
    authorize :update

    load_policy perform_automatic_deletion: false, delete_permitted: true, update_permitted: true
  end

  def post
    authorize :create

    load_policy perform_automatic_deletion: false, delete_permitted: false, update_permitted: false
  end

  protected

  def load_policy perform_automatic_deletion:, delete_permitted:, update_permitted:
    policy_version = PolicyVersion.new \
      role: current_user, policy: resource, policy_text: policy_text
    policy_version.perform_automatic_deletion = perform_automatic_deletion
    policy_version.delete_permitted = delete_permitted
    policy_version.update_permitted = update_permitted
    policy_version.save
    loader = Loader::Orchestrate.new policy_version, context: policy_context
    loader.load

    created_roles = loader.new_roles.select do |role|
      %w(user host).member?(role.kind)
    end.inject({}) do |memo, role|
      credentials = Credentials[role: role] || Credentials.create(role: role)
      memo[role.id] = { id: role.id, api_key: credentials.api_key }
      memo
    end

    render json: {
      created_roles: created_roles,
      version: policy_version.version
    }, status: :created
  end

  def policy_text
    case request.content_type
    when 'multipart/form-data'
      p multipart_data
      multipart_data[:policy]
    else
      request.raw_post
    end
  end

  def policy_context
    multipart_data.reject { |k,v| k == :policy }
  end

  def multipart_data
    @multipart_data ||= parse_multipart_data
  end

  def parse_multipart_data
    boundary = MultipartParser::Reader::extract_boundary_value(request.headers['CONTENT_TYPE'])
    reader = MultipartParser::Reader.new(boundary)

    parts={}

    reader.on_part do |part|
      pn = part.name.to_sym
      part.on_data do |partial_data|
        if parts[pn].nil?
          parts[pn] = partial_data
        else
          parts[pn] = [parts[pn]] unless parts[pn].kind_of?(Array)
          parts[pn] << partial_data
        end
      end
    end

    reader.on_error do |err|
      $stderr.puts("Error: #{err}")
    end

    reader.write request.raw_post.encode(crlf_newline: true)
    reader.ended? or raise Exception, 'truncated multipart message'

    parts
  end

  def find_or_create_root_policy
    Loader::Types.find_or_create_root_policy account
  end

  private

  def concurrent_load _exception
    response.headers['Retry-After'] = retry_delay
    render json: {
      error: {
        code: "policy_conflict",
        message: "Concurrent policy load in progress, please retry"
      }
    }, status: :conflict
  end

  # Delay in seconds to advise the client to wait before retrying on conflict.
  # It's randomized to avoid request bunching.
  def retry_delay
    rand 1..8
  end
end
