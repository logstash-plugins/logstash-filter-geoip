require "digest"


module LogStash module Filters module Geoip module Util

  def get_file_path(filename)
    ::File.join(::File.expand_path("../../../../vendor/", ::File.dirname(__FILE__)), filename)
  end

  def file_exist?(path)
    !path.nil? && ::File.exist?(path) && !::File.empty?(path)
  end

  def md5(file_path)
    file_exist?(file_path) ? Digest::MD5.hexdigest(::File.read(file_path)): ""
  end

end end end end